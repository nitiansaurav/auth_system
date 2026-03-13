import User from "../models/user.js";

export const getAllUsers = async (req, res) => {
  try {
    const users = await User.find({}, "-password");

    res.status(200).json({
      count: users.length,
      users
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch users",
      error: error.message
    });
  }
};

export const toggleUserStatus = async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.body; // "active" | "suspended"

    if (!["active", "suspended"].includes(status)) {
      return res.status(400).json({
        message: "Invalid status"
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { status },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    res.json({
      message: `User ${status} successfully`,
      user
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to update user status",
      error: error.message
    });
  }
};

export const promoteToAdmin = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    if (user.role === "admin") {
      return res.status(400).json({
        message: "User is already an admin"
      });
    }

    user.role = "admin";
    await user.save();

    res.json({
      message: "User promoted to admin",
      user
    });
  } catch (error) {
    res.status(500).json({
      message: "Failed to promote user",
      error: error.message
    });
  }
};