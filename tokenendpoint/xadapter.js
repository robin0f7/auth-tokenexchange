/* eslint-disable */
'use strict';

const assert = require('assert');
const redis = require('redis')

assert(process.env.GCP_PROJECT, 'process.env.GCP_PROJECT missing');

const REDIS_CONNECTION_STRING = process.env.REDIS_CONNECTION_STRING || 'http://localhost:6379';
// const REDIS_CONNECTION_STRING = process.env.REDIS_CONNECTION_STRING || 'http://10.54.0.3:6379';
const REDIS_KEY_PATH = process.env.REDIS_KEY_PATH || 'tokenator/tokenendpoint'


// Import the Secret Manager client and instantiate it:
const SecretManagerServiceClient = require('@google-cloud/secret-manager').SecretManagerServiceClient;
// import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

const epochTime = (date = Date.now()) => Math.floor(date / 1000);

function grantKeyFor(id) {
  return `grant:${id}`;
}

function sessionUidKeyFor(id) {
  return `sessionUid:${id}`;
}

function userCodeKeyFor(userCode) {
  return `userCode:${userCode}`;
}

const grantable = new Set([
  'AccessToken',
  'RefreshToken',
  //'AuthorizationCode',
  //'DeviceCode',
  //'BackchannelAuthenticationRequest',
]);


class GCPSecretsAdapter {

  /**
   *
   * Creates an instance of Adapter for an oidc-provider model.
   *
   * @constructor
   * @param {string} name Name of the oidc-provider model. One of "Grant, "Session", "AccessToken",
   * "AuthorizationCode", "RefreshToken", "ClientCredentials", "Client", "InitialAccessToken",
   * "RegistrationAccessToken", "DeviceCode", "Interaction", "ReplayDetection",
   * "BackchannelAuthenticationRequest", or "PushedAuthorizationRequest"
   *
   */
  constructor(name) {
    this.model = name;
    this.secrets = new SecretManagerServiceClient();
    this.redis = redis.createClient({url: REDIS_CONNECTION_STRING});
    this.redis.on('error', err => console.error('ERR:REDIS:', err));
  }

  /**
   * getApplication gets the client details from redis
   * This should be called before attempting to obtain the indicated
   * client secret from secrets manater. It is also invoked after the secret is
   * verified via findAccounts. It is at that point that node-oidc adds the
   * returned custom_claims  to the jwt.
   * @param {clientid} clientid
   * @returns 
   */
  static async getApplication(clientid) {

    var path = `${REDIS_KEY_PATH}/clients/${clientid}`
    // const url = process.env.APPREGISTRATIONS_URL + "/" + clientid;
    console.info(`getApplication: looking for clientid==${clientid}, path=${path}`)

    const client = await this.redis.hGetAll(path)
    .catch(err => {
      console.error(`failed to get ${path}`, err)
      throw err;
    });

    return client;
  }

  /**
   *
   * Return previously stored instance of an oidc-provider model.
   *
   * @return {Promise} Promise fulfilled with what was previously stored for the id (when found and
   * not dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
   * when encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  async find(id) {

    var client = await GCPSecretsAdapter.getApplication(id);
    if (!client) {
      return undefined;
    }

    // var result = await client.getSecret(app.wallet_key_name);
    const parent = `projects/${process.env.GCP_PROJECT}`
    const name = `${parent}/tokenator-client-secret-${id}`;
    var [secret] = await this.client.getSecret(name);
    return {
      client_id: id,
      client_secret: secret,
      grant_types: ['client_credentials'],
      redirect_uris: [],
      response_types: [],
      // + other client properties
    }
  }

  key(id) {
    return `${this.model}:${id}`;
  }

  /**
   *
   * Update or Create an instance of an oidc-provider model.
   * 
   * NOTE: Apprently structured access tokens are never saved to the adapter -
   * only opaque ones. So possibly this method should just throw
   * 
   *  "BREAKING CHANGE: Only opaque access tokens get stored using the adapter."
   *   -- node-oidc main commit 84c3a5cdb78b8ffda53e2cbebd135bc262b27d4d
   * )
   * 
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier that oidc-provider will use to reference this model instance for
   * future operations.
   * @param {object} payload Object with all properties intended for storage.
   * @param {integer} expiresIn Number of seconds intended for this model to be stored.
   *
   */
  async upsert(id, payload, expiresIn) {

    const key = this.key(id);

    if (this.model === 'Session') {
      storage.set(sessionUidKeyFor(payload.uid), id, expiresIn * 1000);
    }

    const { grantId, userCode } = payload;
    if (grantable.has(this.name) && grantId) {
      const grantKey = grantKeyFor(grantId);
      const grant = storage.get(grantKey);
      if (!grant) {
        storage.set(grantKey, [key]);
      } else {
        grant.push(key);
      }
    }

    if (userCode) {
      storage.set(userCodeKeyFor(userCode), id, expiresIn * 1000);
    }

    storage.set(key, payload, expiresIn * 1000);
  }

  /**
   *
   * Return previously stored instance of DeviceCode by the end-user entered user code. You only
   * need this method for the deviceFlow feature
   *
   * @return {Promise} Promise fulfilled with the stored device code object (when found and not
   * dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
   * when encountered.
   * @param {string} userCode the user_code value associated with a DeviceCode instance
   *
   */
  async findByUserCode(userCode) {
    const id = storage.get(userCodeKeyFor(userCode));
    return this.find(id);
  }

  /**
   *
   * Return previously stored instance of Session by its uid reference property.
   *
   * @return {Promise} Promise fulfilled with the stored session object (when found and not
   * dropped yet due to expiration) or falsy value when not found anymore. Rejected with error
   * when encountered.
   * @param {string} uid the uid value associated with a Session instance
   *
   */
  async findByUid(uid) {
    const id = storage.get(sessionUidKeyFor(uid));
    return this.find(id);
  }

  /**
   *
   * Mark a stored oidc-provider model as consumed (not yet expired though!). Future finds for this
   * id should be fulfilled with an object containing additional property named "consumed" with a
   * truthy value (timestamp, date, boolean, etc).
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  async consume(id) {
    storage.get(this.key(id)).consumed = epochTime();
  }

  /**
   *
   * Destroy/Drop/Remove a stored oidc-provider model. Future finds for this id should be fulfilled
   * with falsy values.
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  async destroy(id) {
    const key = this.key(id);
    storage.delete(key);
  }

  /**
   *
   * Destroy/Drop/Remove a stored oidc-provider model by its grantId property reference. Future
   * finds for all tokens having this grantId value should be fulfilled with falsy values.
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} grantId the grantId value associated with a this model's instance
   *
   */
  async revokeByGrantId(grantId) {
    const grantKey = grantKeyFor(grantId);
    const grant = storage.get(grantKey);
    if (grant) {
      grant.forEach((token) => storage.delete(token));
      storage.delete(grantKey);
    }
  }
}
module.exports = GCPSecretsAdapter;