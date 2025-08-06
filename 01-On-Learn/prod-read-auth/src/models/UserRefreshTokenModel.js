const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "UserModel",
      required: [true, "please provide user-id to store token"],
    },
    token: {
      type: String,
      required: [true, "please provide token"],
      unique: true,
    },
    ipAddress: { type: String, required: true },
    userAgent: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now, index: true },
  },
  { timestamps: true }
);

const UserRefreshTokenModel =
  mongoose.models.UserRefreshTokenModel ||
  mongoose.model("UserRefreshTokenModel", refreshTokenSchema);

module.exports = UserRefreshTokenModel;
