const jwt = require("jsonwebtoken");

const isTokenExpired = (token) => {
  const decodedToken = jwt.decode(token); // use `token` passed to function
  if (!decodedToken || !decodedToken.exp) return true; // handle malformed token

  const currentTime = Date.now() / 1000; // in seconds
  return decodedToken.exp < currentTime;
};

module.exports = isTokenExpired;
