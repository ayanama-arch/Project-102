const mongoose = require("mongoose");

const userRefreshTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  token: { type: String, required: true },
  blacklisted: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, expires: "5d" },
});

const UserRefreshTokenModel =
  mongoose.models.UserRefreshTokenModel ||
  mongoose.model("UserRefreshTokenModel", userRefreshTokenSchema);

module.exports = UserRefreshTokenModel;
