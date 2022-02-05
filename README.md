# Tokenator

Derive tokens for internal services based on id tokens & custom claims from federated oauth2/openid connect providers

## Start Here

tokenator/rrr docker-compose up
runs rrr network

tokenator docker-compose up
runs the exchange on the same network as rrr

tokenator/rrr/rrr/node0

plugins.json && tokenator-config.json configure the json-rpc api security and the integration with tokenendpoint

# Plan

* [ ] Load the provider white list of allowed api scopes (which limit the client scopes) from configmap
* [ ] Load client configuration from config map (for now)
* [ ] deploy to cluster and get explicit curl exchange working
* [ ] Try traefik ForwardAuth with the deployed tokenator
* [ ] Add iam identity & service account for the node token exchange if we need one
* [ ] make this specific to making tokens for geth rpcs
* [ ] In the token exchange, look  up the identity in the adapter and read the per identity scopes from redis
* [ ] OPTIONALY load the signing key from GPC Secrets (will need service account here for sure)
* [ ] Add GCP Secrets to tf
* [ ] Add benchblock support for JSON-API Security config docker & k8s
* [ ] Add support for RS256 id_token_signed_response_alg (and put an RSA key in the providers signing key set)
* [ ] Remove all interactions


## alowed scopes

* provider has master white list. no one gets anything not in that.
* the client config for the relying party gets a white list that can further limit the scopes for tokens exchanged by that client id
* the identity in each token is looked up in the storage fronted by our adapter.js. If a record is found, it limits the scopes available to that specific identity.
* Otherwise a default scope whitelist for identities not known to the adapter backend is applied.


Use traefik's AuthForward to do the token exchange. Can try that now, even
though the permisions on the token arent perfect. That should let us use tls
issuer