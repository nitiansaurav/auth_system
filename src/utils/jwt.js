// generate access token and verify access token

import jwt from "jsonwebtoken";

// ==============================
// Generate Access Token
export const generateAccessToken = (user) => {
  return jwt.sign(
    {
      sub: user._id,      // standard JWT subject
      role: user.role    // authorization support
    },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "30m"
    }
  );
};


// ==============================
// Verify Access Token
export const verifyAccessToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

