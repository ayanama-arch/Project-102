const mongoose = require("mongoose");

const connectDB = async () => {
  if (mongoose.connection.readyState === 1) {
    console.log("⚠️ DB is already connected");
    return;
  }

  try {
    await mongoose.connect(process.env.MONGO_URI, {
      dbName: "on-learn",
    });
    console.log("✅ DB connected successfully");
  } catch (error) {
    console.error("❌ DB connection failed:", error.message);
    process.exit(1); // stop the app if DB fails
  }
};

module.exports = connectDB;
