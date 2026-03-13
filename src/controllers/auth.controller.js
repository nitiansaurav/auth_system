import crypto from "crypto";
import bcrypt from "bcrypt";
import User from "../models/user.js";
import VerificationToken from "../models/tokenVerification.js";
import RefreshToken from "../models/RefreshToken.model.js";
import { generateAccessToken, } from "../utils/jwt.js";
import { rotateRefreshToken } from "../service/token.service.js";

export const register = async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    //  Basic validation
    if (!name || !password) {
      return res.status(400).json({
        message: "Name and password are required"
      });
    }

    if (!email && !phone) {
      return res.status(400).json({
        message: "Email or phone is required"
      });
    }

    // Check if user already exists
    if (email) {
      const existingEmail = await User.findOne({ email });
      if (existingEmail) {
        return res.status(409).json({ message: "Email already registered" });
      }
    }

    if (phone) {
      const existingPhone = await User.findOne({ phone });
      if (existingPhone) {
        return res.status(409).json({ message: "Phone already registered" });
      }
    }

    //  Create user (password hashing handled by model)
    const user = await User.create({
      name,
      email,
      phone,
      password
    });

    // Generate OTP (6-digit)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Hash OTP
    const hashedOtp = await bcrypt.hash(otp, 10);

    //  Save OTP in VerificationToken
    await VerificationToken.create({
      userId: user._id,
      type: email ? "email_verification" : "phone_verification",
      token: hashedOtp,
      expiresAt: new Date(Date.now() + 60 * 1000) // 1 minutes
    });

    //  TEMP: log OTP (replace with email/SMS later)
    console.log("OTP:", otp);

    //  Response
    res.status(201).json({
      message: "User registered successfully. Verify OTP to activate account.",
      userId: user._id
    });

  } catch (error) {
    res.status(500).json({
      message: "Registration failed",
      error: error.message
    });
  }
};


export const login = async (req, res) => {
  try {
    const { email, phone, password } = req.body;

    // 1️⃣ Basic validation
    if ((!email && !phone) || !password) {
      return res.status(400).json({
        message: "Email or phone and password are required"
      });
    }

    // 2️⃣ Find user
    const user = await User.findOne(
      email ? { email } : { phone }
    ).select("+password");

    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    // 3️⃣ Account status
    if (user.status !== "active") {
      return res.status(403).json({
        message: "Account is suspended"
      });
    }

    // 4️⃣ Verification check
    if (email && !user.isEmailVerified) {
      return res.status(403).json({
        message: "Email not verified"
      });
    }

    if (phone && !user.isPhoneVerified) {
      return res.status(403).json({
        message: "Phone not verified"
      });
    }

    // 5️⃣ Password check
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    // 6️⃣ Update last login
    user.lastLoginAt = new Date();
    await user.save();

    // 7️⃣ Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // 8️⃣ Save refresh token in DB
    await RefreshToken.create({
      userId: user._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    // 9️⃣ Set refresh token as HttpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,        // HTTPS only
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    // 🔟 Success response
    res.status(200).json({
      message: "Login successful",
      accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      }
    });

  } catch (error) {
    res.status(500).json({
      message: "Login failed",
      error: error.message
    });
  }
};



//
// controller for refreshing access token
export const refreshAccessToken = async (req, res) => {
  try {
    const oldToken = req.cookies.refreshToken;

    if (!oldToken) {
      return res.status(401).json({ message: "Refresh token missing" });
    }

    // Rotate refresh token (old revoke + new issue)
    const { newRefreshToken ,userId } = await rotateRefreshToken(oldToken , req);

    // fetch user to generate access token
    const user = await User.findById(userId);

    if(!user || user.status !== "active"){
      return res.status(401).json({message : "user not active"});
    }

   // generate access token
   const accessToken = generateAccessToken(user);

   // set new refresh token cookie
   res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
   })

   // send new access token
   return res.status(200).json({
      accessToken
    });
   

  } catch (error) {
    res.status(401).json({
      message: "Invalid or expired refresh token"
    });
  }
};

// controller for logout 
export const logout = async (req, res) => {
  try {
    // 1️⃣ Get refresh token from cookie
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      // 2️⃣ Revoke refresh token in DB
      await RefreshToken.updateOne(
        { token: refreshToken },
        { revokedAt: new Date() }
      );
    }

    // 3️⃣ Clear cookie from browser
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,     // HTTPS
      sameSite: "strict"
    });

    res.status(200).json({
      message: "Logged out successfully"
    });

  } catch (error) {
    res.status(500).json({
      message: "Logout failed",
      error: error.message
    });
  }
};