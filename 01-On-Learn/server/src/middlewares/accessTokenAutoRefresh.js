// This middleware will set Authorization Header and will refresh Access token on expire
// if we use the middleware we won't have to explicitly make request to refresh-token api url

const { ErrorHandler, ErrorCodes } = require("../utils/error-handler");
const isTokenExpired = require("../utils/isTokenExpired");
const refreshAccessToken = require("../utils/refreshAccessToken");
const setTokenCookies = require("../utils/setTokenCookies");
const TryCatch = require("../utils/try-catch");

const accessTokenAutoRefresh = TryCatch(async (req, res, next) => {
  let accessToken = req.cookies.accessToken;


  if (!accessToken || isTokenExpired(accessToken)) {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken)
      return next(
        new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
      );

    const {
      newAccessToken,
      newRefreshToken,
      newAccessTokenExp,
      newRefreshTokenExp,
    } = await refreshAccessToken(req, res, next);

    setTokenCookies(
      res,
      newAccessToken,
      newRefreshToken,
      newAccessTokenExp,
      newRefreshTokenExp
    );
    accessToken = newAccessToken;
  }
  req.headers["authorization"] = `Bearer ${accessToken}`;

  next();
});

module.exports = accessTokenAutoRefresh;
