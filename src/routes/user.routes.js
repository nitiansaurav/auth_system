import express from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { changePassword } from "../controllers/user.controller.js";
import { deleteAccount } from "../controllers/user.controller.js";

const router = express.Router();

// 🔐 Get logged-in user's profile
router.get("/profile", authMiddleware, (req, res) => {
  res.status(200).json({
    message: "Profile fetched successfully",
    user: req.user
  });
});

// Update profile (example)
router.put("/profile", authMiddleware, async (req, res) => {
  const { name } = req.body;

  if (name) {
    req.user.name = name;
    await req.user.save();
  }

  res.json({
    message: "Profile updated successfully",
    user: req.user
  });
});

//  Change password (logged-in user)
router.put("/change-password", authMiddleware, changePassword);

//  Delete account (secure)
router.delete("/delete-account", authMiddleware, deleteAccount);

export default router;