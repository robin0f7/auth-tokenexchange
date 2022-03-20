// Based on examples from:
// https://github.com/panva/node-oidc-provider
// https://github.com/panva/node-oidc-provider-example/tree/main/03-oidc-views-accounts

import path from 'path';
import express from 'express';
import bodyParser from 'body-parser';
import fs from 'fs';
import Provider from 'oidc-provider';

import constantEquals from 'oidc-provider/lib/helpers/constant_equals.js';
// local imports
import Adapter from './adapter.js';
import {decodeAPIKeyIDSecret} from './tokenutils.js';
import registerTokenExchangeGrant from './tokenexchange.js';

// custom routes for interation UI
// check we have all the config we need from the environment
// middleware to add "no caching" headers
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || 300
const PATH_PREFIX = process.env.PATH_PREFIX || ""
const PORT = process.env.PORT || 3000;
const PROVIDER = process.env.PROVIDER || "https://iona.thaumagen.com";
const CLIENTS = JSON.parse(fs.readFileSync(process.env.CLIENTS_FILE));
const CLIENT_SCOPES = ["email", "openid", "rpc://admin_nodeInfo", "rpc://net_*", "rpc://eth_*", "rpc://rpc_modules"];

// middleware to prefix the requrst url for any deployment specific path 
// components so that the redirect responses go to the correct places
function setReqUrlPath(req, res, next) {
    req.originalUrl = `${PATH_PREFIX}${req.originalUrl}`;
    console.log('Request URL:', req.originalUrl)
    next();
}

// middleware to parse URL encoded request body
const parse = bodyParser.urlencoded({ extended: false });

// create the express server app
const expressApp = express();
expressApp.set('trust proxy', true);
expressApp.set('view engine', 'ejs');
expressApp.set('views', path.resolve(path.dirname(''), 'views'));

console.log("-------- %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% --------------------");

Adapter.connect();
const jwks = {keys: [JSON.parse(fs.readFileSync(process.env.SIGNING_SECRET_FILE))]};

async function compareClientSecret(actual) {
    const b = await decodeAPIKeyIDSecret(actual);
    const derivedKey = b.toString('base64');
    return constantEquals(this.clientSecret, derivedKey, 1000);
}
class ExtendedProvider extends Provider {
    constructor(issuer, setup) {
        super(issuer, setup);

        // Override the compareClientSecret as we do not store the secret in our
        // database. The provider find() method is only given the id. And, to
        // satisfy the original compareClientSecret it must fill in the
        // clientSecret field. That requires us to store it in the database.
        // Instead we store a derived key and compare by reconstruction.
        this.Client.prototype.compareClientSecret = compareClientSecret;
    }

    // Note: This also works for the Client class (but not seemingly for OIDCContext)
    // get Client() { return super.Client; }
}

const oidc = new ExtendedProvider(`${PROVIDER}`, {
    adapter: Adapter,
    clients: CLIENTS,
    // clients cant enable scopes beyond those configured here
    scopes: CLIENT_SCOPES,
    clientDefaults: {
        id_token_signed_response_alg: "ES256",
        grant_types: ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"]
    },
    pkce: {
        required: () => false,
    },

    // add claims for extra scopes to id token as well as access token
    // https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#id-token-does-not-include-claims-other-than-sub
    conformIdTokenClaims: false,
    // define the claims for each scope
    claims: {
        aud: `${PROVIDER}`
    },
    // include the keystore
    jwks,
    ttl: {
        Session: 30,

        AccessToken: parseInt(ACCESS_TOKEN_TTL),

        ClientCredentials: function (ctx, token, client) {
            const defaultTTL = parseInt(ACCESS_TOKEN_TTL);
            if (token.resourceServer) {
                return token.resourceServer.accessTokenTTL || defaultTTL;
            }
            return defaultTTL;
        }
    },

    interactions: {
        url(ctx, interaction) {
            return `${PATH_PREFIX}/interaction/${interaction.uid}`;
        },
    },
    extraTokenClaims: async (ctx, token) => {
        console.log("extraTokenClaims: ", token);

        if (! ["ClientCredentials", "AccessToken", "IdToken"].includes(token.kind)) {
            console.log(`extraTokenClaims: unsupported token kind ${token.kind}`);
            return undefined;
        }

        // The customer is not allowed to sneak these into the token via there extra claims.
        const reject_claims = {
            // all oidc rfc 7519
            "iss": true,
            "sub": true,
            "aud": true,
            "exp": true,
            "nbf": true,
            "iat": true,
            "jti": true
        }

        // const app = await adapter.getApplication(token.clientId);
        var extra = {};
        // for (const [key, value] of Object.entries(app.custom_claims)) {

        //     // Check the explicitly rejected claims
        //     if (key.toLowerCase() in reject_claims) {
        //         console.log(`extraTokenClaims: rejecting custom_claim ${key}, claim name is reserved`);
        //         continue;
        //     }

        //     extra[key] = value;
        // }

        return extra;

    },
    features: {
        clientCredentials: { enabled: true },
        introspection: { enabled: true },
        // disable the packaged interactions
        devInteractions: { enabled: false },
        rpInitiatedLogout: { enabled: false },
        resourceIndicators: {
            // From the node-oidc docs:
            // "Client Credentials grant must only contain a single resource parameter." 
            // -- https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#featuresresourceindicators
            // The resource parameter MUST be an absoloute URI and SHOULD be
            // the most specific URI possible for the protected resource.
            // -- https://datatracker.ietf.org/doc/html/rfc8707#section-2
            // Lastly, for client_credentials, the resource SHOULD be copied to the aud.
            defaultResource: (ctx, client, oneOf) => {

                // XXX: want a way to configure these

                // This is resource if none is specifically requested by the client.
                console.log("defaultResource: ", client, oneOf, process.env.DEFAULT_RESOURCE_INDICATOR);
                return process.env.DEFAULT_RESOURCE_INDICATOR;
            },
            enabled: true,
            getResourceServerInfo: (ctx, resourceIndicator, client) => {
                // XXX: client.clientid here rather than env.CLIENT_ID
                console.log("getResourceServerInfo: ", resourceIndicator, client)

                // The recomendation is to use extraClientMetadata to
                // pre-register resource indicators. 
                if (resourceIndicator != process.env.RESOURCE_INDICATOR) {
                    console.log(`bespoke resourceIndicator got ${resourceIndicator}, expected ${process.env.DEFAULT_RESOURCE_INDICATOR}`)
                    // throw errors.InvalidTarget();
                }

                // No audience needs to be set here. For
                // client_credentials, node-oidc ignores us if we do.
                return ({
                    scope: 'profile email',
                    accessTokenFormat: 'jwt',
                });

                // return ({
                //     scope: 'profile email',
                //     audience: process.env.CLIENT_ID,
                //     accessTokenFormat: 'jwt',
                // });
            }
        }
    },
});

oidc.on('assign.client', (ctx, value) => {
    console.log(value);
});

registerTokenExchangeGrant(oidc);

oidc.proxy = true;
// leave the rest of the requests to be handled by oidc-provider,
// there's a catch-all 404 there
expressApp.use(setReqUrlPath, oidc.callback(), (req, res) => { console.log(res);});

expressApp.listen(PORT);