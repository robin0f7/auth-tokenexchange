import { Buffer } from 'buffer';
import got from 'got';

function unverifiedDecodePayload(token) {
  const textDecoder = new TextDecoder()
  return JSON.parse(textDecoder.decode(Buffer.from(token.split('.')[1], 'base64')));
};

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

export {unverifiedDecodePayload, getWellKnownOpenIDConf};