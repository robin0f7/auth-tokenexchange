// The  point of the token exchange grant is to integrate and trust identity
// and authorization from an external platform. We are trusting the external
// identity provider (of the original subject token) to assert the identity.
// We then exchange that external token for a new 'impersonating' token. We
// put the claims and scopes on the new token that are appropriate  to the
// local application. No consent is required here as the resources for those
// scopes and claims do not leave the local application. We don't need to add
// everything here: There is still the 'extraTokenClaims' implementaion on our
// provider. That can be used to add claims issued by local client credentials
// and also exchanged tokens but in a uniform way.
//
// For this exchange, the 'application' is the collection of clients configured
// for the provider. scope in any client enabling this grant defines the
// superset of scopes that can be added.

import * as jose from 'jose';
// import oidcerrors from 'oidc-provider/lib/helpers/errors.js'
import instance from 'oidc-provider/lib/helpers/weak_cache.js';
import * as calculate_thumbprint from 'oidc-provider/lib/helpers/calculate_thumbprint.js';
const thumbprint = calculate_thumbprint["x5t#S256"];
import dpopValidate from 'oidc-provider/lib/helpers/validate_dpop.js';
// import resolveResource from 'oidc-provider/lib/helpers/resolve_resource.js';
import formatters from 'oidc-provider/lib/helpers/formatters.js';
import resolveResource from 'oidc-provider/lib/helpers/resolve_resource.js';

// local imports
import * as errors from './errors.js'
import {unverifiedDecodePayload, getWellKnownOpenIDConf} from "./tokenutils.js"

const parameters = [
  'audience', 'resource', 'scope', 'requested_token_type',
  'subject_token', 'subject_token_type',
  'actor_token', 'actor_token_type'
];
const allowedDuplicateParameters = ['audience', 'resource'];
const grantType = 'urn:ietf:params:oauth:grant-type:token-exchange';

function difference(array, values) {
  return array.filter((value) => values.indexOf(value) === -1)
}

async function tokenExchangeHandler(ctx, next) {
  // ctx.oidc.params holds the parsed parameters
  // ctx.oidc.client has the authenticated client

  const conf = instance(ctx.oidc.provider).configuration();

  // const p = ctx.oidc.provider;
  // const conf = p.configuration;

  // your grant implementation
  // see /lib/actions/grants for references on how to instantiate and issue tokens
  console.log('hello tokenexchange');
  console.log(JSON.stringify(ctx.oidc.params))
  const {
    conformIdTokenClaims,
    features: {
      dPoP: { iatTolerance },
      mTLS: { getCertificate },
      resourceIndicators,
    },
  } = conf;

  const {
    Account, AccessToken, IdToken, ReplayDetection,
  } = ctx.oidc.provider;
  const { client } = ctx.oidc;

  // [rfc8693 2.1 Request] subject_token and subject_token_type are REQUIRED

  const subTokB64 = ctx.oidc.params.subject_token;
  const subTokType = ctx.oidc.params.subject_token_type;

  // [rfc8693 2.1 Request]
  // > In processing the request, the authorization server MUST perform the
  // appropriate validation procedures for the indicated token type and,
  // if the actor token is present, also perform the appropriate
  // validation procedures for its indicated token type

  // console.log("---- protected header ----");
  
  // var header = jose.decodeProtectedHeader(subTokB64.split(".")[0]);
  // console.log(JSON.stringify(header))

  var payload = unverifiedDecodePayload(subTokB64);

  const openIDWellKnown = await getWellKnownOpenIDConf(payload.iss);

  // TODO: cache the remote keyset
  const JWKS = jose.createRemoteJWKSet(new URL(openIDWellKnown.jwks_uri));
  let subjectToken;
  try {
    const res = await jose.jwtVerify(subTokB64, JWKS);
    subjectToken = res.payload;
  }
  catch(err) {
    throw new errors.SubjectTokenVerifyFailed(err);
  }

  let cert;
  if (client.tlsClientCertificateBoundAccessTokens || subjectToken['x5t#S256']) {
    cert = getCertificate(ctx);
    if (!cert) {
      throw new errors.InvalidGrant('mutual TLS client certificate not provided');
    }
  }

  if (subjectToken['x5t#S256'] && subjectToken['x5t#S256'] !== thumbprint(cert)) {
    throw new InvalidGrant('failed x5t#S256 verification');
  }

  if (ctx.oidc.params.scope) {
    const clientScopes = [...client.scope.split(' ')];
    const missing = difference([...ctx.oidc.requestParamScopes], [...clientScopes]);

    if (missing.length !== 0) {
      throw new errors.RequestedScopesDenied(
        `scopes not allowed ${formatters.pluralize('scope', missing.length)}: ${missing.join(' ')}`);
    }
  }

  const dPoP = await dpopValidate(ctx);

  if (dPoP) {
    const unique = await ReplayDetection.unique(
      client.clientId, dPoP.jti, dPoP.iat + iatTolerance,
    );

    ctx.assert(unique, new InvalidGrant('DPoP Token Replay detected'));
  }

  // XXX: TODO resource indicators possibly a better way to do this

  const at = new AccessToken({
    // [rfc8693 2.1] issued token sub 'typically' == subjectToken.sub
    sub: subjectToken.sub,
    aud: ctx.oidc.params.audience,
    client
  });

  // Above, we reject if any of the requested are missing.
  if (ctx.oidc.params.scope) {
    at.scope = ctx.oidc.params.scope;
  }


  // const resource = await resolveResource(
  //   ctx, subjectToken, { resourceIndicators }, scope,
  // );

  // the token type is taken from the resource server
  at.resourceServer = new ctx.oidc.provider.ResourceServer(subjectToken.iss, {
    audience: ctx.oidc.params.audience,
    accessTokenFormat: "jwt"
  });

  if (client.tlsClientCertificateBoundAccessTokens) {
    at.setThumbprint('x5t', cert);
  }

  if (dPoP) {
    at.setThumbprint('jkt', dPoP.thumbprint);
  }

  if (at.gty && !at.gty.endsWith(gty)) {
    at.gty = `${at.gty} ${gty}`;
  }

  // We can remove claims. We can add claims that are specific to our application context.
  at.claims = subjectToken.claims;

  ctx.oidc.entity('AccessToken', at);
  const accessToken = await at.save(); // -> saves to our adapter
  // const accessToken = at;

  const scope = ctx.oidc.requestParamScopes;

  let idToken;
  if (scope && scope.has('openid')) {
    // const claims = filterClaims(refreshToken.claims, 'id_token', grant);
    // const rejected = grant.getRejectedOIDCClaims();
    const token = new IdToken(({
      ...subjectToken.claims,
      acr: subjectToken.acr,
      amr: subjectToken.amr,
      auth_time: subjectToken.authTime,
    }), { ctx });

    token.scope = [...scope].join(' ')
    token.mask = claims;

    token.set('nonce', subjectToken.nonce);
    token.set('at_hash', accessToken);
    token.set('sid', subjectToken.sid);

    idToken = await token.issue({ use: 'idtoken' });
  }

  ctx.body = {
    access_token: accessToken,
    expires_in: at.expiration,
    id_token: idToken,
    scope: at.scope,
    token_type: at.tokenType,
  };

  await next();
}

function registerTokenExchangeGrant(provider) {
    provider.registerGrantType(grantType, tokenExchangeHandler, parameters, allowedDuplicateParameters);
}

export default registerTokenExchangeGrant;