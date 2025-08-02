const jwt = require("jsonwebtoken");

const { ErrorHandler, ErrorCodes } = require("./error-handler");

const setAuthHeader = async (req, res, next) => {
  const accessToken = req.cookies.accessToken;

  //   check is token Expired
  if (!accessToken)
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
    );

  const decodedToken = jwt.decode(accessToken);
  const currentTime = Date.now() / 1000;

  if (decodedToken.exp < currentTime)
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
    );

  req.headers["authorization"] = `Bearer ${accessToken}`;
  next();
};

module.exports = setAuthHeader;
