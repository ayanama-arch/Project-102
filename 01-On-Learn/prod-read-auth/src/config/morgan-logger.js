const morgan = require("morgan");
const rfs = require("rotating-file-stream");
const fs = require("fs");
const path = require("path");

const logDirectory = path.join(__dirname, "../logs");

// Ensure log directory exists
fs.existsSync(logDirectory) || fs.mkdirSync(logDirectory);

// Create a rotating write stream (rotates daily)
const accessLogStream = rfs.createStream("access.log", {
  interval: "1d", // rotate daily
  path: logDirectory,
  compress: "gzip", // compress old logs
});

// Define format based on environment
const getMorganMiddleware = (env) => {
  if (env === "production") {
    // Apache combined format for production
    return morgan("combined", { stream: accessLogStream });
  } else {
    // Colorful dev logging to console
    return morgan("dev");
  }
};

module.exports = getMorganMiddleware;
