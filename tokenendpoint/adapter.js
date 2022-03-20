let APIKEYSTORE_ADDRESS;

import got from 'got';

const grantable = [
    'AccessToken'
];

class Adapter {
  constructor(oidc, name) {
    this.oidc = oidc;
    this.name = name;
  }
    
  async upsert(id, data, expiresIn) {
    console.log(`[${this.name}]upsert ${id}`);
    throw "upsert not implemented by this adapter";
  }

  async find(id) {

    const client = {
      grant_types: ["client_credentials"],
      redirect_uris: [],
      response_types: []
    };

    const url = `http://${APIKEYSTORE_ADDRESS}/clients/${id}`;
    console.log(`[${this.name}] find ${id} ${url}`);

    const data = await got(url).json();

    // The provider implementation MUST be specialised to perform the key
    // derivation. We can't do it here.
    data["client_secret"] = data.derived_key;

    return {...client, ...data};
  }

  async consume(id) {
    console.log(`[${this.name}] consume ${id}`);
    throw "consume not implemented by this adapter";
  }
  async destroy(id) {
    console.log(`[${this.name}] destroy ${id}`);
    throw "destroy not implemented by this adapter";
  }
  static connect() {
    if (!process.env.APIKEYSTORE_ADDRESS)
        throw "APIKEYSTORE_ADDRESS empty or not set";

    APIKEYSTORE_ADDRESS = process.env.APIKEYSTORE_ADDRESS;
    console.log(`Connected`);
  }
}

export default Adapter;