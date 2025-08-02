const bcrypt = require("bcrypt");
const TryCatch = require("../boiler-plate/try-catch");
const { ErrorCodes, ErrorHandler } = require("../boiler-plate/error-handler");
const ApiResponse = require("../boiler-plate/api-response");
const UserModel = require("../models/UserModel");

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
  } else {
    return ApiResponse.validationError(
      res,
      "username already exist, please try another username to continue"
    );
  }

  //   Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = await UserModel.create({
    firstName,
    lastName,
    userName,
    email,
    password: hashedPassword,
  });

  //   Send OTP on Mail

  return ApiResponse.success(res, newUser, "new user created successfully");
});

const UserController = { createUser };
module.exports = UserController;
