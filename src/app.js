import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

import authRoutes from "./routes/auth.routes.js";
import userRoutes from "./routes/user.routes.js";
import adminRoutes from "./routes/admin.routes.js";

const app = express();

/*  CORS MUST BE FIRST */
app.use(cors()); // for all origin


app.use(express.json());
app.use(cookieParser());

// routes

app.get("/", (req, res) => {
  res.send("API is running");
});

app.use("/auth", authRoutes);
app.use("/user", userRoutes);
app.use("/admin", adminRoutes); 



export default app;