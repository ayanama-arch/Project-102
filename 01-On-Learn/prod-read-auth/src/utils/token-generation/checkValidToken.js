const jwt = require("jsonwebtoken");
const UserModel = require("../../models/UserModel");
const TryCatch = require("../../boiler-plate/try-catch");
const {
  ErrorHandler,
  ErrorCodes,
} = require("../../boiler-plate/error-handler");
const UserRefreshTokenModel = require("../../models/UserRefreshTokenModel");
const { sendSuspiciousLoginMail } = require("../../config/send-email");

const checkValidRefreshToken = TryCatch(async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;
  const ipAddress = getClientIP(req);
  const userAgent = req.headers["user-agent"] || "Unknown";

  const decodedToken = jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET
  );

  const user = await UserModel.findById({ _id: decodedToken._id });
  if (!user)
    return next(
      new ErrorHandler(
        ErrorCodes.AUTH_TOKEN_EXPIRED,
        "please login again to continue"
      )
    );

  const existingRefreshToken = await UserRefreshTokenModel.findOne({
    userId: decodedToken._id,
    token: refreshToken,
  });

  if (
    existingRefreshToken.isActive === false ||
    existingRefreshToken.ipAddress !== ipAddress ||
    existingRefreshToken.userAgent !== userAgent
  ) {
    await sendSuspiciousLoginMail(user);
    await UserRefreshTokenModel.deleteMany({ userId: user._id });
  }

  if (!existingRefreshToken || existingRefreshToken.isActive === false)
    return next(
      new ErrorHandler(ErrorCodes.FORBIDDEN, "please login again to continue")
    );
});

module.exports = checkValidRefreshToken;
