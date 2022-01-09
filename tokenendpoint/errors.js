
import oidcerrors from 'oidc-provider/lib/helpers/errors.js'

class _SubjectTokenVerifyFailed extends oidcerrors.OIDCProviderError {
    constructor(err) {
      super(401, 'invalid_subject_token');
      Error.captureStackTrace(this, this.constructor);
      const m = err.message.replace(/"/g, '');
      Object.assign(this, { error_description: m });
    }
}

class _TokenatorError extends Error {
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
// 
// class _ClaimsError extends TokenatorError {
//     error_description = "missing or invalid claims";
// 
//     constructor(detail) {
//         super(403, "invalid_claims");
//         Error.captureStackTrace(this, this.constructor);
//         Object.assign(this, {error_detail: detail});
//     }
// }
export const TokenatorError = _TokenatorError;
export const SubjectTokenVerifyFailed = _SubjectTokenVerifyFailed;
// export const ClaimsError = TokenatorError;