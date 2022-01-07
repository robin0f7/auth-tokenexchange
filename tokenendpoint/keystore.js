const assert = require('assert');
const jose = require('node-jose');
const fs = require('fs');

// Setup JWKS
assert(process.env.SIGNING_SECRET_FILE, 'process.env.SIGNING_SECRET_FILE missing');

const key = JSON.parse(fs.readFileSync(process.env.SIGNING_SECRET_FILE));

const promise = new Promise((resolve, reject) => {
    jose.JWK.asKey(key).
        then((result) => {
            // {result} is a jose.JWK.Key
            resolve(result.keystore.toJSON(true));
        });
});

module.exports = promise;
