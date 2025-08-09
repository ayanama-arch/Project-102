const bcrypt = require("bcrypt");
const TryCatch = require("../boiler-plate/try-catch");
const { ErrorCodes, ErrorHandler } = require("../boiler-plate/error-handler");
const ApiResponse = require("../boiler-plate/api-response");
const UserModel = require("../models/UserModel");
const { sendOtpVerificationMail } = require("../config/send-email");
const EmailVerify = require("../models/EmailVerify");
const getClientIP = require("../utils/client-ip");
const UserRefreshTokenModel = require("../models/UserRefreshTokenModel");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/token-generation/generateToken");
const setCookies = require("../utils/setCookies");

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

  await UserRefreshTokenModel.deleteMany({userId:user._id})

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
  const user = req.user
  if(!user){
    return next(new ErrorHandler(ErrorCodes.UNAUTHORIZED,'please login to continue'))
  }
  const existingUser = await UserModel.find({email:user.email}).select('-password')

  return ApiResponse.success(res,existingUser)
});

const UserController = {
  createUser,
  verifyEmail,
  resendOtp,
  loginUser,
  getProfile,
};
module.exports = UserController;
