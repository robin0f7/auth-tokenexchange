
import * as oidcerrors from 'oidc-provider/lib/helpers/errors.js'

class SubjectTokenVerifyFailed extends oidcerrors.OIDCProviderError {
    constructor(message, err) {
      super(401, 'invalid_subject_token');
      Error.captureStackTrace(this, this.constructor);
      const m = (message || err.message || "unknown error").replace(/"/g, '');
      Object.assign(this, { error_description: m });
    }
}

class RequestedScopesDenied extends oidcerrors.OIDCProviderError {
    constructor(message, err) {
      super(403, 'requested_scopes_denied');
      Error.captureStackTrace(this, this.constructor);
      const m = (message || err.message).replace(/"/g, '');
      Object.assign(this, { error_description: m });
    }
}


class TokenatorError extends Error {
    allow_redirect = true;
    constructor(status, message) {
        super(message);
        this.name = this.constructor.name;
        this.message = message;
        this.error = message;
        this.status = status;
        this.statusCode = status;
        this.expose = status < 500;
    }
}

export {SubjectTokenVerifyFailed, RequestedScopesDenied, TokenatorError};
export const {InvalidToken} = oidcerrors;