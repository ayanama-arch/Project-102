// Package Import
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// Utils Import
const TryCatch = require("../../utils/try-catch");
const { ErrorHandler, ErrorCodes } = require("../../utils/error-handler");
const ApiResponse = require("../../utils/api-response");
const {
  sendOtpVerificationMail,
  transporter,
} = require("../../config/email-otp");

// Validation Import
const validateUserInput = require("../../validators/user-register");

// Models Import
const User = require("../../models/user.model");
const EmailVerify = require("../../models/verifyEmail.model");
const generateAccessAndRefreshToken = require("../../utils/generate-token");
const setTokenCookies = require("../../utils/setTokenCookies");
const refreshAccessToken = require("../../utils/refreshAccessToken");
const UserRefreshTokenModel = require("../../models/userRefreshToken.model");

// Controllers

const createUser = TryCatch(async (req, res, next) => {
  const { fullName, email, password } = req.body;

  if (!fullName || !email || !password)
    return next(
      new ErrorHandler(
        ErrorCodes.NOT_FOUND,
        "please provide valid user details to register"
      )
    );

  // Validating fields with zod
  const { isValid } = validateUserInput({ fullName, email, password });

  if (!isValid)
    return next(
      new ErrorHandler(ErrorCodes.BAD_REQUEST, "user credentials are not valid")
    );

  const existingUser = await User.findOne({ email });
  if (existingUser)
    return next(new ErrorHandler(ErrorCodes.CONFLICT, "user already existts"));

  //   Hashing Password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Send OTP to verify

  //   Creating New User
  const newUser = await User.create({
    fullName,
    email,
    password: hashedPassword,
  });

  const otpResponse = await sendOtpVerificationMail(newUser);
  if (otpResponse.success === false)
    return next(new ErrorHandler(ErrorCodes.BAD_REQUEST, "otp mail failed"));

  return ApiResponse.success(res, newUser, "user created successfully");
});

const verifyEmail = TryCatch(async (req, res, next) => {
  const { email, otp } = req.body;

  // 1. Check user exists
  const user = await User.findOne({ email });
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

  const user = await User.findOne({ email });
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
  const { email, password } = req.body;

  if (!email || !password)
    return next(
      new ErrorHandler(
        ErrorCodes.BAD_REQUEST,
        "please provide valid credentials"
      )
    );

  const user = await User.findOne({ email });
  if (!user)
    return next(
      new ErrorHandler(ErrorCodes.NOT_FOUND, "invalid email or password")
    );

  if (!user.isVerified)
    return next(
      new ErrorHandler(
        ErrorCodes.FORBIDDEN,
        "please verify your email to continue"
      )
    );

  const validUser = await bcrypt.compare(password, user.password);

  if (!validUser)
    return next(
      new ErrorHandler(ErrorCodes.NOT_FOUND, "invalid email or password")
    );

  const { accessToken, accessTokenExp, refreshToken, refreshTokenExp } =
    await generateAccessAndRefreshToken(user);

  // Set Cookie
  setTokenCookies(
    res,
    accessToken,
    refreshToken,
    accessTokenExp,
    refreshTokenExp
  );

  const responseObj = {
    user: {
      _id: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
    },
    access_token: accessToken,
    refresh_token: refreshToken,
    access_token_exp: accessTokenExp,
    is_auth: true,
  };
  ApiResponse.success(res, responseObj, "login successful");
});

const getNewAccessToken = TryCatch(async (req, res, next) => {
  // Get new access Token using Refresh Token
  const {
    newAccessToken,
    newRefreshToken,
    newAccessTokenExp,
    newRefreshTokenExp,
  } = await refreshAccessToken(req, res, next);

  // Dry new tokens to Cookie
  setTokenCookies(
    res,
    newAccessToken,
    newRefreshToken,
    newAccessTokenExp,
    newRefreshTokenExp
  );

  const responseObj = {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
    accessTokenExp: newAccessTokenExp,
    refreshTokenExp: newRefreshTokenExp,
  };

  return ApiResponse.success(
    res,
    responseObj,
    "new token refresh successfully"
  );
});

const getUser = TryCatch((req, res, next) => {
  ApiResponse.success(res, { user: req.user });
});

const logoutUser = TryCatch(async (req, res, next) => {
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.clearCookie("is_auth");

  // Blacklist Refresh Token
  const refreshToken = req.cookies.refreshToken;
  await UserRefreshTokenModel.findOneAndUpdate(
    { token: refreshToken },
    { $set: { blacklisted: true } }
  );

  ApiResponse.success(res, "logout successfully");
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

  await User.findByIdAndUpdate(req.user._id, {
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
  const user = await User.findOne({ email });
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
        <p>Hi ${user.fullName.split(" ")[0]},</p>
        <p>Hello ${
          user.name
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

  const user = await User.findById(decodedToken.userId);

  if (!user)
    return next(new ErrorHandler(ErrorCodes.NOT_FOUND, "User not found"));

  // Hash new password
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(password, salt);

  await user.save();

  return ApiResponse.success(res, "password reset successfully");
});

module.exports = {
  createUser,
  verifyEmail,
  resendOtp,
  loginUser,
  getNewAccessToken,
  getUser,
  logoutUser,
  changePassword,
  sendUserPasswordResetEmail,
  verifyUserResetPassword,
};
