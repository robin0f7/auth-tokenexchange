# Tokenator

Derive tokens for internal services based on id tokens & custom claims from federated oauth2/openid connect providers
## alowed scopes (this is tbd)

* [ ] provider has master white list. no one gets anything not in that.
* [/] the client config for the relying party gets a white list that can further limit the scopes for tokens exchanged by that client id
* [ ] the identity in each token is looked up in the storage fronted by our adapter.js. If a record is found, it limits the scopes available to that specific identity.
* [ ] Otherwise a default scope whitelist for identities not known to the adapter backend is applied.

# Tooling

## Usage from 1st checkout

1. clone the repo
2. task bootstrap NAMESPACE=yourchoice
   SKAFFOLD_DEFAULT_REPO defaults to eu.gcr.io/$(kubectl config current-context).
   If that doesn't suit, add SKAFFOLD_DEFAULT_REPO=yourchoice to the bootstrap
   overrides.
3. task generate CLIENTID_SECRET_FILE=path/to/clientidsecrets.env
  after the first run, you don't need to pass CLIENTID_SECRET_FILE again if
  re-generating other materials
4. task build
5. task deploy

## Manifests & cluster requirements

The kubernetes manifests assume the presence of a traefik proxy instance with
the kubernetes CRD provider enabled. If the RBAC rules don't allow the instance
to watch all namespaces, set the NAMESPACE variable to match treafiks when
bootstraping

If not using GCP, be sure to set SKAFFOLD_DEFAULT_REPO when bootstraping

## Taskfile conventions

The current kubernetes context when bootstraping is *sticky*. Tasks all set the
kubernetes context explicitly to the value recorded when bootstrap ran.
