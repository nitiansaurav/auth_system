import mongoose from "mongoose";

const connectDB = async () => {
  try {
    // Prevent multiple connections in dev (nodemon / hot reload)
    if (mongoose.connection.readyState === 1) {
      console.log("MongoDB already connected");
      return;
    }

    const mongoURI = process.env.MONGO_URI;

    if (!mongoURI) {
      throw new Error("MONGODB_URI is not defined in .env file");
    }

    const connection = await mongoose.connect(mongoURI, {
      dbName: "authentication", // your database name
      autoIndex: true,
    });

    console.log(
      `MongoDB Connected: ${connection.connection.host}/${connection.connection.name}`
    );
  } catch (error) {
    console.error("MongoDB connection error:", error.message);
    process.exit(1); // stop server if DB fails
  }
};

export default connectDB;