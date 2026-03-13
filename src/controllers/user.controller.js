import bcrypt from "bcrypt";
import User from "../models/user.js";

export const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    //  Validation
    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        message: "Current password and new password are required"
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        message: "New password must be at least 6 characters"
      });
    }

    //  Get logged-in user (from authMiddleware)
    const user = await User.findById(req.user._id).select("+password");

    //  Verify current password
    const isMatch = await bcrypt.compare(
      currentPassword,
      user.password
    );

    if (!isMatch) {
      return res.status(401).json({
        message: "Current password is incorrect"
      });
    }

    //  Prevent same password reuse
    const isSame = await bcrypt.compare(newPassword, user.password);
    if (isSame) {
      return res.status(400).json({
        message: "New password must be different from current password"
      });
    }

    //  Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    await user.save();

    // Success response
    res.status(200).json({
      message: "Password changed successfully"
    });

  } catch (error) {
    res.status(500).json({
      message: "Failed to change password",
      error: error.message
    });
  }
};


// controller for deleting account by user
export const deleteAccount = async (req, res) => {
  try {
    const { password } = req.body;

    // 1️⃣ Validate input
    if (!password) {
      return res.status(400).json({
        message: "Password is required to delete account"
      });
    }

    // 2️⃣ Get logged-in user with password
    const user = await User.findById(req.user._id).select("+password");

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    // 3️⃣ Verify password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        message: "Incorrect password"
      });
    }

    // 4️⃣ Delete user account
    await User.findByIdAndDelete(user._id);

    // (optional) future: delete related data (orders, sessions, etc.)

    res.status(200).json({
      message: "Account deleted permanently"
    });

  } catch (error) {
    res.status(500).json({
      message: "Failed to delete account",
      error: error.message
    });
  }
};