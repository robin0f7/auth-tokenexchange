// Based on examples from:
// https://github.com/panva/node-oidc-provider
// https://github.com/panva/node-oidc-provider-example/tree/main/03-oidc-views-accounts

const assert = require('assert');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
// const errors = require('oidc-provider/lib/helpers/errors');
const Provider = require('oidc-provider');
const adapter = require("./adapter");
const InteractionRoutes = require("./interaction");
const registerTokenExchangeGrant = require("./tokenexchange.js");

// simple JWKS keystore
const keystorePromise = require('./keystore');

// custom routes for interation UI
// check we have all the config we need from the environment
// middleware to add "no caching" headers
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || 300
const PATH_PREFIX = process.env.PATH_PREFIX || "/tokens"
const PORT = process.env.PORT || 3000;
const PROVIDER = process.env.PROVIDER || "http://localhost";
const clients = JSON.parse(fs.readFileSync(process.env.CLIENTS_FILE));

function setNoCache(req, res, next) {
    res.set('Pragma', 'no-cache');
    res.set('Cache-Control', 'no-cache, no-store');
    next();
}

// middleware to prefix the requrst url for any deployment specific path 
// components so that the redirect responses go to the correct places
function setReqUrlPath(req, res, next) {
    req.originalUrl = `${PATH_PREFIX}${req.originalUrl}`;
    console.log('Request URL:', req.originalUrl)
    next();
}

function findAccount(ctx, sub, token) {
    console.log(`findAccount: looking for account sub==${sub}`)
}

// middleware to parse URL encoded request body
const parse = bodyParser.urlencoded({ extended: false });

// create the express server app
const expressApp = express();
expressApp.set('trust proxy', true);
expressApp.set('view engine', 'ejs');
expressApp.set('views', path.resolve(__dirname, 'views'));

// configure the OIDC provider with the populated keystore, add the custom
// routes and start the express server 
keystorePromise.then((jwks) => {
    let claims

    console.log("-------- ######################## --------------------");

    const oidc = new Provider(`${PROVIDER}`, {
        adapter: adapter,
        clients: clients,
        pkce: {
            required: () => false,
        },

        // add claims for extra scopes to id token as well as access token
        // https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#id-token-does-not-include-claims-other-than-sub
        conformIdTokenClaims: false,
        // define the claims for each scope
        claims,
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

        findAccount: findAccount,
        interactions: {
            url(ctx, interaction) {
                return `${PATH_PREFIX}/interaction/${interaction.uid}`;
            },
        },
        extraTokenClaims: async (ctx, token) => {
            console.log("extraTokenClaims: ", token);

            // We only add to the token claims for client credentials flow
            if (token.kind !== 'ClientCredentials') {
                console.log("extraTokenClaims: not client credentials token, so not adding claims");
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

            const app = await adapter.getApplication(token.clientId);
            var extra = {};
            for (const [key, value] of Object.entries(app.custom_claims)) {

                // Check the explicitly rejected claims
                if (key.toLowerCase() in reject_claims) {
                    console.log(`extraTokenClaims: rejecting custom_claim ${key}, claim name is reserved`);
                    continue;
                }

                extra[key] = value;
            }

            return extra;

        },
        features: {
            // disable the packaged interactions
            devInteractions: { enabled: false },
            rpInitiatedLogout: { enabled: true },
            clientCredentials: { enabled: true },
            introspection: { enabled: false },
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

    registerTokenExchangeGrant(oidc);

    oidc.proxy = true;

    // add user interaction routes
    const interaction = new InteractionRoutes(oidc, PATH_PREFIX);

    // TODO: could probably do something better than using a class and binding the object
    // to the member pointer
    expressApp.get(
        '/interaction/:uid',
        setNoCache,
        interaction.interact.bind(interaction)
    );
    expressApp.post(
        '/interaction/:uid/login',
        setNoCache,
        parse,
        interaction.login.bind(interaction)
    );
    expressApp.post(
        '/interaction/:uid/confirm',
        setNoCache,
        parse,
        interaction.confirm.bind(interaction)
    );
    expressApp.get(
        '/interaction/:uid/abort',
        setNoCache,
        interaction.abort.bind(interaction)
    );

    // leave the rest of the requests to be handled by oidc-provider,
    // there's a catch-all 404 there
    expressApp.use(setReqUrlPath, oidc.callback(), (req, res) => { console.log(res);});

    expressApp.listen(PORT);
}).catch((err) => {
    process.exitCode = 1;
    console.error(err);
});
