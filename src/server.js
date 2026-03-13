import dotenv from "dotenv";
dotenv.config(); // MUST be first

import app from "./app.js";
import connectDB from "./config/db.js";

const PORT = process.env.PORT || 4000;

// Start server after DB connect
const startServer = async () => {
  try {
    await connectDB(); // DB first
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error.message);
    process.exit(1);
  }
};

startServer();