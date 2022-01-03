const assert = require('assert');

// simple account model (user list)
const Account = require('./account');

class InteractionRoutes {
    // derived from
    // https://github.com/panva/node-oidc-provider-example/tree/main/03-oidc-views-accounts

    constructor(oidc, urlPrefix) {
        this.oidc = oidc;
        this.urlPrefix = urlPrefix;
    }

    async interact(req, res, next) {
        try {
            const details = await this.oidc.interactionDetails(req, res);
            const {
                uid, prompt, params,
            } = details;
            const client = await this.oidc.Client.find(params.client_id);
            if (prompt.name === 'login') {
                return res.render('login', {
                    client,
                    uid,
                    details: prompt.details,
                    params,
                    title: 'Sign-in',
                    flash: undefined,
                    urlPrefix: this.urlPrefix,
                });
            }
            return res.render('interaction', {
                client,
                uid,
                details: prompt.details,
                params,
                title: 'Authorize',
                urlPrefix: this.urlPrefix,
            });
        } catch (err) {
            return next(err);
        }
    }
    async login(req, res, next) {
        try {
            const { uid, prompt, params } = await this.oidc.interactionDetails(req, res);
            assert.strictEqual(prompt.name, 'login');
            const client = await this.oidc.Client.find(params.client_id);
            const accountId = await Account.authenticate(req.body.email, req.body.password);
            if (!accountId) {
                res.render('login', {
                    client,
                    uid,
                    details: prompt.details,
                    params: {
                        ...params,
                        login_hint: req.body.email,
                    },
                    title: 'Sign-in',
                    flash: 'Invalid email or password.',
                    urlPrefix: this.urlPrefix,
                });
                return;
            }
            const result = {
                login: { accountId },
            };
            await this.oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
        } catch (err) {
            next(err);
        }
    }
    async confirm(req, res, next) {
        try {
            const interactionDetails = await this.oidc.interactionDetails(req, res);
            const { prompt: { name, details }, params, session: { accountId } } = interactionDetails;
            assert.strictEqual(name, 'consent');
            let { grantId } = interactionDetails;
            let grant;
            console.log(details);
            if (grantId) {
                // we'll be modifying existing grant in existing session
                grant = await this.oidc.Grant.find(grantId);
            } else {
                // we're establishing a new grant
                grant = new this.oidc.Grant({
                    accountId,
                    clientId: params.client_id,
                });
            }
            if (details.missingOIDCScope) {
                grant.addOIDCScope(details.missingOIDCScope.join(' '));
                console.log(details.missingOIDCScope);
                // use grant.rejectOIDCScope to reject a subset or the whole thing
            }
            if (details.missingOIDCClaims) {
                grant.addOIDCClaims(details.missingOIDCClaims);
                console.log(details.missingOIDCClaims);
                // use grant.rejectOIDCClaims to reject a subset or the whole thing
            }
            if (details.missingResourceScopes) {
            // eslint-disable-next-line no-restricted-syntax
                for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
                    grant.addResourceScope(indicator, scopes.join(' '));
                    // use grant.rejectResourceScope to reject a subset or the whole thing
                }
            }
            grantId = await grant.save();
            const consent = {};
            if (!interactionDetails.grantId) {
                // we don't have to pass grantId to consent, we're just modifying existing one
                consent.grantId = grantId;
            }
            const result = { consent };
            await this.oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
        } catch (err) {
            next(err);
        }
    }
    async abort(req, res, next) {
        try {
            const result = {
                error: 'access_denied',
                error_description: 'End-User aborted interaction',
            };
            await this.oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
        } catch (err) {
            next(err);
        }
    }
};

module.exports = InteractionRoutes
