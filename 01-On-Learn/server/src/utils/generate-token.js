const jwt = require("jsonwebtoken");
const UserRefreshTokenModel = require("../models/userRefreshToken.model");

const generateAccessAndRefreshToken = async (user) => {
  try {
    const payload = {
      _id: user._id,
      email: user.email,
      role: user.role,
    };

    // Access Token (1 minute)
    const accessTokenExp = Math.floor(Date.now() / 1000) + 60 * 1;
    const accessToken = jwt.sign(
      { ...payload, exp: accessTokenExp },
      process.env.ACCESS_TOKEN_SECRET
    );

    // Refresh Token (15 days)
    const refreshTokenExp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 15;
    const refreshToken = jwt.sign(
      { ...payload, exp: refreshTokenExp },
      process.env.REFRESH_TOKEN_SECRET
    );

    const existingToken = await UserRefreshTokenModel.findOne({
      userId: user._id,
    });

    // Remove old Refresh token if present
    if (existingToken) await existingToken.deleteOne({ userId: user._id });

    // Save new Refresh Token
    await new UserRefreshTokenModel({
      userId: user._id,
      token: refreshToken,
    }).save();

    return { accessToken, refreshToken, accessTokenExp, refreshTokenExp };
  } catch (error) {
    console.error("Error generating tokens:", error);
    throw new Error("Token generation failed");
  }
};

module.exports = generateAccessAndRefreshToken;
