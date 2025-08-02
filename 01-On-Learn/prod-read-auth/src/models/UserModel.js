const mongoose = require("mongoose");
const validator = require("validator");

const userSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: [true, "please provide first name"],
    },
    lastName: {
      type: String,
      required: [true, "please provide last name"],
    },
    userName: {
      type: String,
      unique: true,
      required: [true, "please provide username"],
      lowercase: true,
      trim: true,
    },
    email: {
      type: String,
      unique: true,
      required: [true, "please provide email"],
      lowercase: true,
      trim: true,
      validate: [validator.isEmail, "please provide valid email"],
    },
    password: {
      type: String,
      required: [true, "please provide password"],
      minlength: [8, "Password must be at least 6 characters long"],
      validate: {
        validator: function (value) {
          // at least one uppercase, one lowercase, one digit
          return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/.test(value);
        },
        message:
          "Password must contain at least one uppercase letter, one lowercase letter, and one number.",
      },
    },
    role: {
      type: String,
      enum: ["admin", "instructor", "student"],
      default: "student",
    },
    avatar: {
      public_id: {
        type: String,
      },
      url: {
        type: String,
        default:
          "https://res.cloudinary.com/dksgrqazo/image/upload/v1754118560/user-icon_qthvuz.png",
      },
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

const UserModel =
  mongoose.models.UserModel || mongoose.model("UserModel", userSchema);

module.exports = UserModel;
