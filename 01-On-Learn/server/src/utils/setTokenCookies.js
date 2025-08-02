const setTokenCookies = (
  res,
  accessToken,
  refreshToken,
  newAccessTokenExp,
  newRefreshTokenExp
) => {
  const accessTokenMaxAge =
    (newAccessTokenExp - Math.floor(Date.now() / 1000)) * 1000;
  const refreshTokenMaxAge =
    (newRefreshTokenExp - Math.floor(Date.now() / 1000)) * 1000;

  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: true,
    maxAge: accessTokenMaxAge,
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    maxAge: refreshTokenMaxAge,
  });
};

module.exports = setTokenCookies;
