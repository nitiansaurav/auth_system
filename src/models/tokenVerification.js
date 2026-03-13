// model for phone email verification token , login otp and password reset 


import mongoose from "mongoose";

const verificationTokenSchema = new mongoose.Schema(
  {
    // Which user this token belongs to
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    // What this token is used for
    type: {
      type: String,
      enum: [
        "email_verification",
        "phone_verification",
        "login_otp",
        "password_reset"
      ],
      required: true
    },

    // Hashed OTP or token (never store raw OTP)
    tokenhash : {
      type: String,
      required: true,
      select: false  // select: false prevents accidental leaks
    },

    // Expiry time (OTP validity)
    expiresAt: {
      type: Date,
      required: true,
    },

    // Prevent reuse
    usedAt: {
    type: Date,
    default: null
    },

    // Optional: limit brute force attempts
    attempts: {
      type: Number,
      default: 0
    },
    blockedUntil: {
    type: Date,
    default: null
    }
  },
  { timestamps: true }
);

// Automatically delete expired tokens (MongoDB TTL index)
verificationTokenSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);

const VerificationToken = mongoose.model(
  "VerificationToken",
  verificationTokenSchema
);

export default VerificationToken;
