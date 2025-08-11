const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const TryCatch = require("../boiler-plate/try-catch");
const { ErrorCodes, ErrorHandler } = require("../boiler-plate/error-handler");
const ApiResponse = require("../boiler-plate/api-response");
const UserModel = require("../models/UserModel");
const { sendOtpVerificationMail, transporter } = require("../config/send-email");
const EmailVerify = require("../models/EmailVerify");
const getClientIP = require("../utils/client-ip");
const UserRefreshTokenModel = require("../models/UserRefreshTokenModel");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/token-generation/generateToken");
const setCookies = require("../utils/setCookies");
const isTokenExpired = require("../utils/token-generation/token-expiration");

const createUser = TryCatch(async (req, res, next) => {
  const { userName, email, password, firstName, lastName } = req.body;

  if (!userName || !email || !password || !firstName || !lastName)
    return next(
      new ErrorHandler(
        ErrorCodes.BAD_REQUEST,
        "please provide all the required fields"
      )
    );

  const userWithEmail = await UserModel.findOne({ email });
  const userWithUserName = await UserModel.findOne({ userName });
  if (userWithEmail && userWithUserName) {
    return ApiResponse.validationError(
      res,
      "username and email already in use, please login to continue"
    );
  } else if (userWithEmail) {
    return ApiResponse.validationError(
      res,
      "email already in use, please login to continue"
    );
  } else if (userWithUserName) {
    return ApiResponse.validationError(
      res,
      "username already exist, please try another username to continue"
    );
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = await UserModel.create({
    firstName,
    lastName,
    userName,
    email,
    password: hashedPassword,
  });

  //   Send OTP on Mail
  const { message, statusCode, success, error } = await sendOtpVerificationMail(
    newUser
  );

  if (!success) return ApiResponse.error(res, message, statusCode, error);

  return ApiResponse.success(res, newUser, "new user created successfully");
});

const verifyEmail = TryCatch(async (req, res, next) => {
  const { email, otp } = req.body;

  // 1. Check user exists
  const user = await UserModel.findOne({ email });
  if (!user)
    return next(new ErrorHandler(ErrorCodes.NOT_FOUND, "User does not exist"));

  // 2. Already verified?
  if (user.isVerified)
    return next(
      new ErrorHandler(ErrorCodes.BAD_REQUEST, "User is already verified")
    );

  // 3. Check OTP exists for user
  const otpRecord = await EmailVerify.findOne({ userId: user._id });
  if (!otpRecord)
    return next(
      new ErrorHandler(ErrorCodes.NOT_FOUND, "OTP has expired or not found")
    );

  // 4. Compare OTP
  if (Number(otp) !== Number(otpRecord.otp))
    return next(
      new ErrorHandler(ErrorCodes.BAD_REQUEST, "OTP provided is incorrect")
    );

  // 5. Mark user as verified
  user.isVerified = true;
  await user.save();

  // 6. Delete OTP record (optional since TTL will delete it soon)
  await EmailVerify.deleteOne({ _id: otpRecord._id });

  // 7. Respond
  ApiResponse.success(res, 200, "OTP verified successfully");
});

const resendOtp = TryCatch(async (req, res, next) => {
  const { email } = req.body;

  const user = await UserModel.findOne({ email });
  if (!user)
    return next(
      new ErrorHandler(ErrorCodes.NOT_FOUND, "Please register the user first.")
    );

  if (user.isVerified)
    return next(
      new ErrorHandler(ErrorCodes.BAD_REQUEST, "User is already verified.")
    );

  const otpResponse = await sendOtpVerificationMail(user);
  if (!otpResponse.success)
    return next(
      new ErrorHandler(
        ErrorCodes.BAD_REQUEST,
        otpResponse.message || "OTP mail failed"
      )
    );

  return ApiResponse.success(res, 200, "OTP sent successfully");
});

const loginUser = TryCatch(async (req, res, next) => {
  const { login, password } = req.body;

  const user = await UserModel.findOne({
    $or: [{ email: login }, { userName: login }],
  });

  if (!user)
    return next(
      new ErrorHandler(ErrorCodes.NOT_FOUND, "invalid login credentials")
    );

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch)
    return next(
      new ErrorHandler(ErrorCodes.NOT_FOUND, "invalid login credentials")
    );

  const { accessToken, accessTokenExp } = generateAccessToken(user);
  const { refreshToken, refreshTokenExp } = generateRefreshToken(user);

  const ipAddress = getClientIP(req);
  const userAgent = req.headers["user-agent"] || "Unknown";

  await UserRefreshTokenModel.deleteMany({ userId: user._id });

  const refreshTokenDoc = new UserRefreshTokenModel({
    token: refreshToken,
    userId: user._id,
    ipAddress,
    userAgent,
    expiresAt: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000),
  });
  await refreshTokenDoc.save();

  // Setting the Cookies
  setCookies(res, refreshToken, refreshTokenExp, accessToken, accessTokenExp);

  return ApiResponse.success(res, {
    accessToken,
    accessTokenExp,
    refreshToken,
    refreshTokenExp,
    user: {
      _id: user._id,
      email: user.email,
      userName: user.userName,
      role: user.role,
    },
  });
});

const getProfile = TryCatch(async (req, res, next) => {
  const user = req.user;
  if (!user) {
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
    );
  }
  const existingUser = await UserModel.find({ email: user.email }).select(
    "-password"
  );

  return ApiResponse.success(res, existingUser);
});

const refreshToken = TryCatch(async (req, res, next) => {
  const cookieRefreshToken = req.cookies?.refreshToken;

  const ipAddress = getClientIP(req);
  const userAgent = req.headers["user-agent"] || "Unknown";

  if (!cookieRefreshToken || isTokenExpired(cookieRefreshToken))
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
    );

  let decodeToken;
  try {
    decodeToken = jwt.verify(
      cookieRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
  } catch (err) {
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
    );
  }

  if (!decodeToken)
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
    );

  const existingRefreshToken = await UserRefreshTokenModel.findOne({
    userId: decodeToken._id,
  });

  // Check IP and User-Agent mismatch
  if (
    existingRefreshToken.ipAddress !== ipAddress ||
    existingRefreshToken.userAgent !== userAgent
  ) {
    // Delete the old refresh token
    await UserRefreshTokenModel.deleteOne({ _id: existingRefreshToken._id });

    return next(
      new ErrorHandler(
        ErrorCodes.UNAUTHORIZED,
        "Refresh token IP/User-Agent mismatch. Please login again."
      )
    );
  }

  if (!existingRefreshToken)
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
    );

  const user = await UserModel.findById(decodeToken._id);
  if (!user)
    return next(
      new ErrorHandler(ErrorCodes.UNAUTHORIZED, "please login to continue")
    );

  const { accessToken, accessTokenExp } = generateAccessToken(user);
  const { refreshToken, refreshTokenExp } = generateRefreshToken(user);

  setCookies(res, refreshToken, refreshTokenExp, accessToken, accessTokenExp);

  return ApiResponse.success(res, "tokens updated successfully");
});

const logout = TryCatch(async (req, res, next) => {
  const user = req.user;

  await UserRefreshTokenModel.deleteOne({ userId: user._id });

  // Clear cookies on client
  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });

  return ApiResponse.success(res, "user logout successfully");
});

const changePassword = TryCatch(async (req, res, next) => {
  const { password, password_confirmation } = req.body;

  if (!password || !password_confirmation)
    return next(
      new ErrorHandler(ErrorCodes.BAD_REQUEST, "invalid credentials")
    );

  if (password !== password_confirmation)
    return next(
      new ErrorHandler(ErrorCodes.BAD_REQUEST, "invalid credentials")
    );

  const salt = await bcrypt.genSalt(10);
  const newHashPassword = await bcrypt.hash(password, salt);

  await UserModel.findByIdAndUpdate(req.user._id, {
    $set: { password: newHashPassword },
  });

  return ApiResponse.success(res, "password changed successfully");
});

const sendUserPasswordResetEmail = TryCatch(async (req, res, next) => {
  const { email } = req.body;
  if (!email)
    return next(
      new ErrorHandler(
        ErrorCodes.BAD_REQUEST,
        "please provide valid credentials"
      )
    );

  // Checking whether user Exist
  const user = await UserModel.findOne({ email });
  if (!user)
    return next(
      new ErrorHandler(
        ErrorCodes.BAD_REQUEST,
        "please provide valid credentials"
      )
    );

  // Generate token for password reset
  const token = jwt.sign(
    { userId: user._id },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );

  // ResetLink
  const resetLink = `${process.env.FRONTEND_HOST}/account/reset-password-confirm?token=${token}`;

  // Send password reset email
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: user.email,
    subject: "Password Reset Link",
    html: `
        <p>Hi ${user.firstName},</p>
        <p>Hello ${
          user.firstName + " " +user.lastName
        }, </p><p>Please <a href="${resetLink}">Click here</a> to reset your password</p>
        <p>If you did not request this, please ignore this email.</p>
        <p>— ON-LEARN Team</p>
      `,
  });

  return ApiResponse.success(
    res,
    "password reset link has been sent, please check your email"
  );
});

const verifyUserResetPassword = TryCatch(async (req, res, next) => {
  const { password, password_confirmation } = req.body;
  const { token } = req.params;

  if (!password || !password_confirmation || !token)
    return next(
      new ErrorHandler(
        ErrorCodes.BAD_REQUEST,
        "please provide valid credentials"
      )
    );

  if (password !== password_confirmation)
    return next(
      new ErrorHandler(
        ErrorCodes.BAD_REQUEST,
        "please provide valid credentials"
      )
    );

  const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

  if (!decodedToken)
    return next(
      new ErrorHandler(
        ErrorCodes.UNAUTHORIZED,
        "please provide valid credentials"
      )
    );

  const user = await UserModel.findById(decodedToken.userId);

  if (!user)
    return next(new ErrorHandler(ErrorCodes.NOT_FOUND, "User not found"));

  // Hash new password
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(password, salt);

  await user.save();

  return ApiResponse.success(res, "password reset successfully");
});


const UserController = {
  createUser,
  verifyEmail,
  resendOtp,
  loginUser,
  getProfile,
  refreshToken,
  logout,
  changePassword,
  sendUserPasswordResetEmail,
  verifyUserResetPassword
};
module.exports = UserController;
