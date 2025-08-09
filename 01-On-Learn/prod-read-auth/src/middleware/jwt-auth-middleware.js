const jwt = require('jsonwebtoken');

function jwtVerifyMiddleware(req, res, next) {
  const token = req.cookies.accessToken; // or from header
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Token invalid or expired' });

    req.user = decoded; // minimal user data from token payload
    next();
  });
}


module.exports = jwtVerifyMiddleware