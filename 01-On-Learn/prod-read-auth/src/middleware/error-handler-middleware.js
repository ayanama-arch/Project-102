const ApiResponse = require("../../../server/src/utils/api-response");

const errorHandlerMiddleware = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || "internal server error";

  return ApiResponse.error(res, message, statusCode, { stack: err.stack });
};

module.exports = errorHandlerMiddleware;
