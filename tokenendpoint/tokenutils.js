import { Buffer } from 'buffer';
import got from 'got';

import {argon2id, argon2Verify} from 'hash-wasm';

function unverifiedDecodePayload(token) {
  const textDecoder = new TextDecoder()
  return JSON.parse(textDecoder.decode(Buffer.from(token.split('.')[1], 'base64')));
};

const apiKeyNumSecretParts = 3;
const apiKeyAlgPart               = 0;
const apiKeySaltPart              = 1;
const apiKeyPasswordPart          = 2;

async function decodeAPIKeyIDSecret(secret) {

  const parts = secret.split('.');
  if (parts.length != apiKeyNumSecretParts)
    throw "secret is not in alg.salt.passord form";

  const alg = parts[apiKeyAlgPart];
  const salt = Buffer.from(parts[apiKeySaltPart], 'base64');
  const password = Buffer.from(parts[apiKeyPasswordPart], 'base64');

  const derivedKey = await argon2id({
    password: password, 
    outputType: 'binary',
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 64*1024, // 64MB
    // memorySize: 64, // 64KB
    hashLength: 32,
  });

  return Buffer.from(derivedKey);
}

async function decodeAPIKey(apikey) {
  const dec = new TextDecoder();

  const s = dec.decode(Buffer.from(apikey, 'base64'));

  var parts = s.split(':');
  if (parts.length != 2)
    throw "invalid apikey. outer format should be clientid:secret";
  const clientId = parts[0]; 
  parts = parts[1].split('.')
  if (parts.length != apiKeyNumSecretParts)
    throw "secret is not in alg.salt.passord form";

  const alg = parts[apiKeyAlgPart];
  const salt = Buffer.from(parts[apiKeySaltPart], 'base64');
  // const password = bin2String(Buffer.from(parts[apiKeyPasswordPart], 'base64'));
  const password = Buffer.from(parts[apiKeyPasswordPart], 'base64');

  const derivedKey = await argon2id({
    password: password, 
    outputType: 'binary',
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 64*1024, // 64MB
    // memorySize: 64, // 64KB
    hashLength: 32,
  });

  return {
    client_id: clientId,
    alg: alg,
    salt: salt,
    password: password,
    derivedKey: Buffer.from(derivedKey),
  }
}

async function getWellKnownOpenIDConf(iss) {
  const url = `${iss}/.well-known/openid-configuration`;

  const res = await got(url, {
    responseType: "json"
  })
  .catch(err => {
    console.error(`failed to get ${url}`, err)
    if (err.response.statusCode == 404) {
      return resolve();
    }
    throw err;
  });
  return res.body;
}

export {
  unverifiedDecodePayload,
  getWellKnownOpenIDConf,
  decodeAPIKey,
  decodeAPIKeyIDSecret
};