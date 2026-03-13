// model for refreshtoken and how it is stored in db

import mongoose from "mongoose";

const refreshTokenSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    refreshtokenHash: {
      type: String,
      required: true,
      index: true,
      select: false
    },

    expiresAt: {
      type: Date,
      required: true,
    },

    //  rotation support
    replacedByToken: {
      type: String,
      default: null
    },

    revokedAt: {
      type: Date,
      default: null
    },
    deviceId: {
      type: String
    },
    ipAddress: {
      type: String
    },
    userAgent: {
      type: String
    }
  },
  { timestamps: true }
);

// TTL
refreshTokenSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);

export default mongoose.model("RefreshToken", refreshTokenSchema);