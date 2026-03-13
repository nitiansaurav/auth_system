import express from "express";
import { register, login , logout } from "../controllers/auth.controller.js";
import { verifyOtp, resendOtp, requestLoginOtp, verifyLoginOtp } from "../controllers/otp.controller.js";
import { requestPasswordReset, resetPassword } from "../controllers/password.controller.js";


const router = express.Router();

// Register & Password Login
router.post("/register", register);
router.post("/login", login);

// Signup OTP
router.post("/verify-otp", verifyOtp);
router.post("/resend-otp", resendOtp);

// Login via OTP
router.post("/login/request-otp", requestLoginOtp);
router.post("/login/verify-otp", verifyLoginOtp);
router.post("/login/resend-otp", requestLoginOtp);

// Forgot password
router.post("/forgot-password", requestPasswordReset);
router.post("/reset-password", resetPassword);

// logout
router.post("/logout", logout);

export default router;