const express = require("express");
const UserController = require("../controllers/user.controller");
const router = express.Router();

router.post("/create", UserController.createUser);
router.post("/verify-otp", UserController.verifyEmail);
router.post("/resend-otp", UserController.resendOtp);
router.post("/login", UserController.loginUser);

module.exports = router;
