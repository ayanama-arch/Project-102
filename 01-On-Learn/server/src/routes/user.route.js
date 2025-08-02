const passport = require("passport");
const express = require("express");
const {
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
} = require("../controllers/user/user.controller");
const setAuthHeader = require("../utils/setAuthHeader");
const accessTokenAutoRefresh = require("../middlewares/accessTokenAutoRefresh");
const router = express.Router();

router.post("/register", createUser);
router.post("/verify-email", verifyEmail);
router.post("/resend-otp", resendOtp);
router.post("/login", loginUser);
router.get("/refresh-token", getNewAccessToken);
router.post("/reset-password-email", sendUserPasswordResetEmail);
router.post("/verify-reset-password", verifyUserResetPassword);
router.post("/verify-reset-password/:token", verifyUserResetPassword);

// Protected Routes
router.get(
  "/me",
  accessTokenAutoRefresh,
  passport.authenticate("jwt", { session: false }),
  getUser
);
router.post(
  "/logout",
  accessTokenAutoRefresh,
  passport.authenticate("jwt", { session: false }),
  logoutUser
);
router.post(
  "/change-password",
  accessTokenAutoRefresh,
  passport.authenticate("jwt", { session: false }),
  changePassword
);

module.exports = router;
