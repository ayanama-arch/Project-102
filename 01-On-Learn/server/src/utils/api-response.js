class ApiResponse {
  static success(
    res,
    data = null,
    message = "Success",
    statusCode = 200,
    meta = {}
  ) {
    return res.status(statusCode).json({
      success: true,
      statusCode,
      message,
      data,
      meta,
      timestamp: Date.now(),
    });
  }

  static created(
    res,
    data = null,
    message = "Resource created successfully",
    meta = {}
  ) {
    return this.success(res, data, message, 201, meta);
  }

  static badRequest(res, message = "Bad request", error = {}, meta = {}) {
    return this.error(res, message, 400, error, meta);
  }

  static unauthorized(res, message = "Unauthorized", error = {}, meta = {}) {
    return this.error(res, message, 401, error, meta);
  }

  static forbidden(res, message = "Forbidden", error = {}, meta = {}) {
    return this.error(res, message, 403, error, meta);
  }

  static notFound(res, message = "Resource not found", error = {}, meta = {}) {
    return this.error(res, message, 404, error, meta);
  }

  static validationError(
    res,
    message = "Validation error",
    error = {},
    meta = {}
  ) {
    return this.error(res, message, 422, error, meta);
  }

  static error(
    res,
    message = "An error occurred",
    statusCode = 500,
    error = {},
    meta = {}
  ) {
    return res.status(statusCode).json({
      success: false,
      statusCode,
      message,
      error,
      meta,
      timestamp: Date.now(),
    });
  }

  static serverError(
    res,
    message = "Internal server error",
    error = {},
    meta = {}
  ) {
    return this.error(res, message, 500, error, meta);
  }
}

module.exports = ApiResponse;
