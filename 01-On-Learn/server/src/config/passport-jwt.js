const { Strategy: JwtStrategy, ExtractJwt } = require("passport-jwt");
const passport = require("passport");
const User = require("../models/user.model");

const opts = {
  secretOrKey: process.env.ACCESS_TOKEN_SECRET,
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
};

passport.use(
  new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
      const user = await User.findById(jwt_payload._id).select("-password");

      if (user) {
        return done(null, user); // ✅ User found, pass to next middleware
      } else {
        return done(null, false); // ❌ No user found
      }
    } catch (err) {
      return done(err, false); // ❌ Error occurred
    }
  })
);
