const path = require("path");
const dotnev = require("dotenv");

const env = process.env.NODE_ENV || "development";

dotnev.config({ path: path.resolve(process.cwd(), `.env.${env}`) });

console.log(`[env] Loaded .env.${env}`);
