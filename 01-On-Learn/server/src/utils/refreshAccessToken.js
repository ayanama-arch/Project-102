const jwt = require("jsonwebtoken");
const UserRefreshTokenModel = require("../models/userRefreshToken.model");
const { ErrorHandler, ErrorCodes } = require("./error-handler");
const User = require("../models/user.model");
const generateAccessAndRefreshToken = require("./generate-token");

const refreshAccessToken = async (req, _, next) => {
  const oldRefreshToken = req.cookies.refreshToken;

  if (!oldRefreshToken)
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "no refresh token found")
    );

  //   Verify refresh Token
  const decodeRefreshToken = jwt.verify(
    oldRefreshToken,
    process.env.REFRESH_TOKEN_SECRET
  );

  const user = await User.findById(decodeRefreshToken._id);

  if (!user)
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
    );

  // Checking token in DB
  const existingRefreshToken = await UserRefreshTokenModel.findOne({
    userId: decodeRefreshToken._id,
    token: oldRefreshToken,
  });

  if (!existingRefreshToken || existingRefreshToken.blacklisted === true)
    return next(
      new ErrorHandler(ErrorCodes.FORBIDDEN, "please login again to continue")
    );

  // Generate New Tokens
  const { accessToken, accessTokenExp, refreshToken, refreshTokenExp } =
    await generateAccessAndRefreshToken(user);

  return {
    newAccessToken: accessToken,
    newRefreshToken: refreshToken,
    newAccessTokenExp: accessTokenExp,
    newRefreshTokenExp: refreshTokenExp,
  };
};

module.exports = refreshAccessToken;
