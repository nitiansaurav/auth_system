import bcrypt from "bcrypt";
import User from "../models/user.js";
import VerificationToken from "../models/tokenVerification.js";


// controller to tequest to reset password
// POST /auth/reset-password
export const requestPasswordReset = async (req, res) => {
  try {
    const { email, phone } = req.body;

    if (!email && !phone) {
      return res.status(400).json({
        message: "Email or phone is required"
      });
    }

    // 1️⃣ Find user
    const user = await User.findOne(email ? { email } : { phone });

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    // 2️⃣ Invalidate previous reset OTPs
    await VerificationToken.updateMany(
      {
        userId: user._id,
        type: "password_reset",
        used: false
      },
      { used: true }
    );

    // 3️⃣ Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);

    // 4️⃣ Save OTP
    await VerificationToken.create({
      userId: user._id,
      type: "password_reset",
      token: hashedOtp,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    // TEMP: send OTP
    console.log("Password reset OTP:", otp);

    res.status(200).json({
      message: "Password reset OTP sent",
      userId: user._id
    });

  } catch (error) {
    res.status(500).json({
      message: "Failed to send reset OTP",
      error: error.message
    });
  }
};


// controller to reset password
export const resetPassword = async (req, res) => {
  try {
    const { userId, otp, newPassword } = req.body;

    if (!userId || !otp || !newPassword) {
      return res.status(400).json({
        message: "UserId, OTP and new password are required"
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters"
      });
    }

    // 1️⃣ Find valid OTP
    const tokenDoc = await VerificationToken.findOne({
      userId,
      type: "password_reset",
      used: false,
      expiresAt: { $gt: new Date() }
    }).select("+token");

    if (!tokenDoc) {
      return res.status(400).json({
        message: "OTP expired or invalid"
      });
    }

    // 2️⃣ Compare OTP
    const isMatch = await bcrypt.compare(otp, tokenDoc.token);

    if (!isMatch) {
      tokenDoc.attempts += 1;
      await tokenDoc.save();

      return res.status(400).json({
        message: "Invalid OTP"
      });
    }

    // 3️⃣ Mark OTP as used
    tokenDoc.used = true;
    await tokenDoc.save();

    // 4️⃣ Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.findByIdAndUpdate(userId, {
      password: hashedPassword
    });

    res.status(200).json({
      message: "Password reset successful. You can now login."
    });

  } catch (error) {
    res.status(500).json({
      message: "Password reset failed",
      error: error.message
    });
  }
};