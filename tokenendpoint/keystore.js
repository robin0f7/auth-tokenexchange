import assert from 'assert';
import * as jose from 'jose';
import { readFileSync } from 'fs';

// Setup JWKS
assert(process.env.SIGNING_SECRET_FILE, 'process.env.SIGNING_SECRET_FILE missing');

const signingKeys = new Promise((resolve, reject) => {
    // XXX: TODO gcpsecret store support
    const jwks = {keys: [JSON.parse(readFileSync(process.env.SIGNING_SECRET_FILE))]};
    resolve(jwks);
});

// const signingKey = jose.importJWK(JSON.parse(readFileSync(process.env.SIGNING_SECRET_FILE)));

export default signingKeys;
