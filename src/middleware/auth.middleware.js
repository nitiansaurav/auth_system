import { verifyAccessToken } from "../utils/jwt.js";
import User from "../models/user.js";

export const authMiddleware = async (req, res, next) => {
  try {
    // 1️⃣ Get token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Authorization token missing"
      });
    }

    const token = authHeader.split(" ")[1];

    // 2️⃣ Verify token
    const decoded = verifyAccessToken(token);
    // decoded => { id, iat, exp }

    // 3️⃣ Fetch user (optional but recommended)
    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({
        message: "User not found"
      });
    }

    if (user.status !== "active") {
      return res.status(403).json({
        message: "Account is suspended"
      });
    }

    // 4️⃣ Attach user to request
    req.user = user;

    // 5️⃣ Continue to controller
    next();

  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired token"
    });
  }
};