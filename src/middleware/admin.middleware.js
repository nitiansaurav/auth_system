export const adminMiddleware = (req, res, next) => {
  // authMiddleware ke baad hi chalega
  // isliye req.user already available hai

  if (!req.user || !req.user.role) {
    return res.status(401).json({
      message: "Unauthorized"
    });
  }

  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Admin access only"
    });
  }

  // user admin hai → allow
  next();
};