require("./config/env-config");
const errorHandlerMiddleware = require("./middleware/error-handler-middleware");
const getMorganMiddleware = require("./config/morgan-logger");
const ApiRoutes = require("./routes/route");

const cookieParser = require('cookie-parser')
const express = require("express");
const connectDB = require("./config/connectDB");
const app = express();

const NODE_ENV = process.env.NODE_ENV || "development";
const PORT = process.env.PORT || 5000;

app.use(getMorganMiddleware(NODE_ENV));
app.use(express.json());
app.use(cookieParser())

app.use(`/api/${process.env.API_VERSION}`, ApiRoutes);

// Error Handling
app.use(errorHandlerMiddleware);

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`server is running at PORT: ${PORT}`);
  });
});
