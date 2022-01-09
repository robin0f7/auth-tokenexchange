import { Buffer } from 'buffer';
import * as jose from 'jose';
// import oidcerrors from 'oidc-provider/lib/helpers/errors.js'
import instance from 'oidc-provider/lib/helpers/weak_cache.js';
import * as calculate_thumbprint from 'oidc-provider/lib/helpers/calculate_thumbprint.js';
const thumbprint = calculate_thumbprint["x5t#S256"];
import dpopValidate from 'oidc-provider/lib/helpers/validate_dpop.js';
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

  console.log("---- unverified ----");
  var payload = unverifiedDecodePayload(subTokB64);
  console.log(JSON.stringify(payload));
  console.log(payload.iss);

  const openIDWellKnown = await getWellKnownOpenIDConf(payload.iss);
  console.log(JSON.stringify(openIDWellKnown));

  // TODO: cache the remote keyset
  const JWKS = jose.createRemoteJWKSet(new URL(openIDWellKnown.jwks_uri));
  let subjectToken;
  try {
    const res = await jose.jwtVerify(subTokB64, JWKS);
    subjectToken = res.payload;

    console.log("---- VERIFIED ----");
    console.log(JSON.stringify(subjectToken));
  }
  catch(err) {
    console.log("---- VERIFY FAILED ----");
    throw new errors.SubjectTokenVerifyFailed(err);
  }

  let cert;
  if (client.tlsClientCertificateBoundAccessTokens || subjectToken['x5t#S256']) {
    cert = getCertificate(ctx);
    if (!cert) {
      throw new InvalidGrant('mutual TLS client certificate not provided');
    }
  }

  if (subjectToken['x5t#S256'] && subjectToken['x5t#S256'] !== thumbprint(cert)) {
    throw new InvalidGrant('failed x5t#S256 verification');
  }

  if (ctx.oidc.params.scope) {
    const missing = difference([...ctx.oidc.requestParamScopes], [...subjectToken.scopes]);

    if (missing.length !== 0) {
      throw new InvalidScope(`token missing requested ${formatters.pluralize('scope', missing.length)}`, missing.join(' '));
    }
  }

  const dPoP = await dpopValidate(ctx);

  if (dPoP) {
    const unique = await ReplayDetection.unique(
      client.clientId, dPoP.jti, dPoP.iat + iatTolerance,
    );

    ctx.assert(unique, new InvalidGrant('DPoP Token Replay detected'));
  }

  const at = new AccessToken({
    // [rfc8693 2.1] issued token sub 'typically' == subjectToken.sub
    sub: subjectToken.sub,
    aud: subjectToken.aud,
    client
  });

  const scope = ctx.oidc.params.scope ? ctx.oidc.requestParamScopes : subjectToken.scopes;
  const resource = await resolveResource(
    ctx, subjectToken, { resourceIndicators }, scope,
  );

  // the token type is taken from the resource server
  at.resourceServer = new ctx.oidc.provider.ResourceServer(subjectToken.iss, {
    audience: ctx.oidc.params.aud,
    scope: scope,
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