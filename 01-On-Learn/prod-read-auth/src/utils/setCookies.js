const setCookies = (
  res,
  refreshToken,
  refreshTokenExp,
  accessToken,
  accessTokenExp
) => {
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: refreshTokenExp,
  });
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: accessTokenExp,
  });
};

module.exports = setCookies;
