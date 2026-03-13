import express from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { adminMiddleware } from "../middleware/admin.middleware.js";
import {
  getAllUsers,
  toggleUserStatus,
  promoteToAdmin
} from "../controllers/admin.controller.js";

const router = express.Router();

// 🔐 Apply admin protection to ALL routes below
router.use(authMiddleware, adminMiddleware);

// ✅ Admin dashboard
router.get("/dashboard", (req, res) => {
  res.json({
    message: "Welcome to admin dashboard",
    admin: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role
    }
  });
});

// ✅ Get all users
router.get("/users", getAllUsers);

// ✅ Suspend / Activate user
router.patch("/users/:userId/status", toggleUserStatus);

// ✅ Promote user to admin
router.patch("/users/:userId/promote", promoteToAdmin);

export default router;