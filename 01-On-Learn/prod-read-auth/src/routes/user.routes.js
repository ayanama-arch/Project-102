const express = require("express");
const UserController = require("../controllers/user.controller");
const accessTokenAutoRefresh = require("../middleware/access-token-auto-refresh");
const jwtVerifyMiddleware = require("../middleware/jwt-auth-middleware");
const router = express.Router();

router.post("/create", UserController.createUser);
router.post("/verify-otp", UserController.verifyEmail);
router.post("/resend-otp", UserController.resendOtp);
router.post("/login", UserController.loginUser);
router.get('/refresh-token',UserController.refreshToken)

// Protected Routes
router.get('/profile',accessTokenAutoRefresh,jwtVerifyMiddleware,UserController.getProfile)
router.get('/logout',accessTokenAutoRefresh,jwtVerifyMiddleware,UserController.logout)

module.exports = router;
