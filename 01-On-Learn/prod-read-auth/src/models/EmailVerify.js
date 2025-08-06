const mongoose = require("mongoose");
const emailVerifySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "UserModel",
    required: true,
  },
  otp: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: "2m",
  },
});

const EmailVerify =
  mongoose.models.EmailVerify ||
  mongoose.model("EmailVerify", emailVerifySchema);

module.exports = EmailVerify;
