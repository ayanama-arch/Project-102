const nodemailer = require("nodemailer");
const EmailVerify = require("../models/EmailVerify");

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendOtpVerificationMail = async (user) => {
  try {
    const otp = Math.floor(1000 + Math.random() * 9000);

    const existingOtp = await EmailVerify.findOne({ userId: user._id });
    if (existingOtp) {
      return {
        success: false,
        statusCode: 429, // Too many requests
        message: "Too many requests. Please wait before requesting a new OTP.",
      };
    }

    await EmailVerify.create({
      userId: user._id,
      otp: otp.toString(),
    });

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: user.email,
      subject: "OTP Verification",
      html: `
        <p>Hi ${user.firstName},</p>
        <p>Your OTP for verifying your email is:</p>
        <h2>${otp}</h2>
        <p>This OTP is valid for the next 2 minutes.</p>
        <p>If you did not request this, please ignore this email.</p>
        <p>— ON-LEARN Team</p>
      `,
    });

    return {
      success: true,
      statusCode: 200,
      message: "OTP sent successfully",
    };
  } catch (error) {
    console.error("OTP email error:", error);
    return {
      success: false,
      statusCode: 500,
      message: "Failed to send OTP",
      error: error.message,
    };
  }
};

const sendSuspiciousLoginMail = async (user, ipAddress, userAgent) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: user.email,
      subject: "Suspicious Login Attempt Detected",
      html: `
        <p>Hi ${user.firstName},</p>
        <p>We noticed a login attempt from a new device or location:</p>
        <ul>
          <li><strong>IP Address:</strong> ${ipAddress}</li>
          <li><strong>Device:</strong> ${userAgent}</li>
        </ul>
        <p>If this was you, you can safely ignore this message. If not, we recommend resetting your password immediately.</p>
        <p>— ON-LEARN Security Team</p>
      `,
    });

    return {
      success: true,
      statusCode: 200,
      message: "Suspicious login alert sent successfully",
    };
  } catch (error) {
    return {
      success: false,
      statusCode: 500,
      message: "Failed to send suspicious login email",
      error: error.message,
    };
  }
};

module.exports = {
  transporter,
  sendOtpVerificationMail,
  sendSuspiciousLoginMail,
};
