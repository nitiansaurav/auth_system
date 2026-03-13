import bcrypt from "bcrypt";
import User from "../models/user.js";
import VerificationToken from "../models/tokenVerification.js";
import { generateAccessToken } from "../utils/jwt.js";

// verify otp controller
// POST /auth/verify-otp
export const verifyOtp = async (req, res) => {
  try {
    const { userId, otp } = req.body;

    // 1️⃣ Basic validation
    if (!userId || !otp) {
      return res.status(400).json({
        message: "UserId and OTP are required"
      });
    }

    // 2️⃣ Find valid OTP token
    const tokenDoc = await VerificationToken.findOne({
      userId,
      used: false,
      expiresAt: { $gt: new Date() }
    }).select("+token");

    if (!tokenDoc) {
      return res.status(400).json({
        message: "OTP expired or invalid"
      });
    }

    // 3️⃣ Compare OTP
    const isMatch = await bcrypt.compare(otp, tokenDoc.token);

    //  Check if OTP is blocked
    if (tokenDoc.blockedUntil && tokenDoc.blockedUntil > new Date()) {
      return res.status(429).json({
        message: "OTP temporarily blocked. Try again after 2 minutes."
      });
    }

    //  OTP incorrect
    if (!isMatch) {
       tokenDoc.attempts += 1;

    //  Block OTP after 3 attempts
    if (tokenDoc.attempts >= 3) {
       tokenDoc.blockedUntil = new Date(Date.now() + 2 * 60 * 1000); // 2 minutes
    }

    await tokenDoc.save();

      return res.status(400).json({
        message:
        tokenDoc.attempts >= 3
        ? "Too many attempts. OTP blocked for 2 minutes."
        : "Invalid OTP"
      });
    }

    // 4️⃣ Mark OTP as used
    tokenDoc.used = true;
    await tokenDoc.save();

    // 5️⃣ Verify user
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    if (tokenDoc.type === "email_verification") {
      user.isEmailVerified = true;
    }

    if (tokenDoc.type === "phone_verification") {
      user.isPhoneVerified = true;
    }

    await user.save();

   // Generate JWT after successful OTP verification
       const token = generateAccessToken(user._id);

       res.status(200).json({
       message: "OTP verified successfully. Account activated.",
       token
    });

  } catch (error) {
    res.status(500).json({
      message: "OTP verification failed",
      error: error.message
    });
  }
};

// resend otp controller
// POST /auth/resend-otp
export const resendOtp = async (req, res) => {
  try {
    const { userId } = req.body;

    // 1️⃣ Validate input
    if (!userId) {
      return res.status(400).json({
        message: "UserId is required"
      });
    }

    // 2️⃣ Find user
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    // 3️⃣ Check if already verified
    if (user.isEmailVerified || user.isPhoneVerified) {
      return res.status(400).json({
        message: "User already verified"
      });
    }

    // 4️⃣ Invalidate previous OTPs
    await VerificationToken.updateMany(
      {
        userId,
        used: false
      },
      { used: true }
    );

    // 5️⃣ Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // 6️⃣ Hash OTP
    const hashedOtp = await bcrypt.hash(otp, 10);

    // 7️⃣ Save new OTP
    await VerificationToken.create({
      userId,
      type: user.email ? "email_verification" : "phone_verification",
      token: hashedOtp,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 min
    });

    // ⚠️ TEMP: log OTP
    console.log("Resent OTP:", otp);

    // 8️⃣ Response
    res.status(200).json({
      message: "OTP resent successfully"
    });

  } catch (error) {
    res.status(500).json({
      message: "Failed to resend OTP",
      error: error.message
    });
  }
};


// request otp for login via otp controller
// POST /auth/login/request-otp
export const requestLoginOtp = async (req, res) => {
  try {
    const { email, phone } = req.body;

    if (!email && !phone) {
      return res.status(400).json({
        message: "Email or phone is required"
      });
    }

    //  Find user
    const user = await User.findOne(email ? { email } : { phone });

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    //  Check verification
    if (email && !user.isEmailVerified) {
      return res.status(403).json({ message: "Email not verified" });
    }

    if (phone && !user.isPhoneVerified) {
      return res.status(403).json({ message: "Phone not verified" });
    }

    //  CHECK ACTIVE OTP (COOLDOWN LOGIC)
    const activeOtp = await VerificationToken.findOne({
      userId: user._id,
      type: "login_otp",
      used: false,
      expiresAt: { $gt: new Date() }
    });

    if (activeOtp) {
      return res.status(429).json({
        message: "OTP already sent. Please wait before requesting again."
      });
    }

    // Invalidate any old unused OTPs (safety)
    await VerificationToken.updateMany(
      { userId: user._id, type: "login_otp", used: false },
      { used: true }
    );

    //  Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);

    //  Save OTP
    await VerificationToken.create({
      userId: user._id,
      type: "login_otp",
      token: hashedOtp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000) // 5 min
    });

    // TEMP: send OTP
    console.log("Login OTP:", otp);

    res.status(200).json({
      message: "OTP sent for login",
      userId: user._id
    });

  } catch (error) {
    res.status(500).json({
      message: "Failed to send login OTP",
      error: error.message
    });
  }
};


// POST /auth/login/verify-otp
export const verifyLoginOtp = async (req, res) => {
  try {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
      return res.status(400).json({
        message: "UserId and OTP are required"
      });
    }

    // 1️⃣ Find valid login OTP
    const tokenDoc = await VerificationToken.findOne({
      userId,
      type: "login_otp",
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

    // 3️⃣ Mark OTP used
    tokenDoc.used = true;
    await tokenDoc.save();

    // 4️⃣ Login user
    const user = await User.findById(userId);

    user.lastLoginAt = new Date();
    await user.save();

    // 5️⃣ JWT (next step)
    const token = generateAccessToken(user._id);

    res.status(200).json({
      message: "Login successful via OTP",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone
      }
      // token
    });

  } catch (error) {
    res.status(500).json({
      message: "OTP login failed",
      error: error.message
    });
  }
};

