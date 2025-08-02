// require("./config/env");
require("./config/env");
require("./config/passport-jwt");

const express = require("express");
const cookieParser = require("cookie-parser");

const errorHandlerMiddleware = require("./middlewares/errorHandlerMiddleware");
const connectDB = require("./config/connectDB");
const indexRoutes = require("./routes/index.route");
const app = express();
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(express.json());
app.use(cookieParser());

// API
app.use("/api/v1", indexRoutes);

// Error Middleware
app.use(errorHandlerMiddleware);

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`server is running at PORT:${PORT}`);
  });
});
