class ErrorHandler extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;

    Error.captureStackTrace(this, this.constructor);
  }
}

const ErrorCodes = {
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,

  INTERNAL_SERVER_ERROR: 500,
  SERVICE_UNAVAILABLE: 503,

  // Optional Custom Codes (if needed)
  VALIDATION_ERROR: 1001,
  AUTH_TOKEN_EXPIRED: 1002,
  RATE_LIMIT_EXCEEDED: 1003,
};

module.exports = { ErrorHandler, ErrorCodes };
