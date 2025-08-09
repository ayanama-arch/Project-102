const jwt = require("jsonwebtoken");

const generateAccessToken = (user) => {
  const payload = {
    _id: user._id,
    email: user.email,
    role: user.role,
  };

  const accessTokenExp = Math.floor(Date.now() / 1000) + 60 * 15;
  const accessToken = jwt.sign(
    { ...payload, exp: accessTokenExp },
    process.env.ACCESS_TOKEN_SECRET
  );

  return { accessToken, accessTokenExp };
};
const generateRefreshToken = (user) => {
  const payload = {
    _id: user._id,
    email: user.email,
    role: user.role,
  };

  const refreshTokenExp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7;
  const refreshToken = jwt.sign(
    { ...payload, exp: refreshTokenExp },
    process.env.REFRESH_TOKEN_SECRET
  );

  return { refreshToken, refreshTokenExp };
};

module.exports = { generateAccessToken, generateRefreshToken };
