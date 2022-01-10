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

Use traefik's AuthForward to do the token exchange. Can try that now, even
though the permisions on the token arent perfect. That should let us use tls
issuer