const TryCatch = require("../boiler-plate/try-catch");
const getClientIP = require("../utils/client-ip");
const checkValidRefreshToken = require("../utils/token-generation/checkValidToken");
const isTokenExpired = require("../utils/token-generation/token-expiration");

const accessTokenAutoRefresh = TryCatch(async (req, res, next) => {
  let accessToken = req.cookies.accessToken;

  if (!accessToken || !isTokenExpired(accessToken)) {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken)
      return next(
        new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
      );

    checkValidRefreshToken(req, res, next);
  }
});
