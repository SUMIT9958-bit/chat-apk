import jwt from 'jsonwebtoken';
import User from '../models/user.model.js';

const protectRoute = async (req, res, next) => {
  try {
    // Check if token exists in cookies
    const token = req.cookies?.jwt || req.headers.authorization?.split(' ')[1]; // fallback to Authorization header
    if (!token) {
      return res.status(401).json({ error: "Unauthorized - No Token Provided" });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res.status(401).json({ error: "Unauthorized - Invalid Token" });
    }

    // Find user by decoded userId
    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    // Attach user object to req
    req.user = user;

    // Proceed to next middleware
    next();
  } catch (error) {
    console.log("Error in protectRoute middleware:", error.message);

    // Distinguish between token-related errors and others
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: "Unauthorized - Token Expired" });
    } else if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: "Unauthorized - Invalid Token" });
    }

    // For other errors, return internal server error
    res.status(500).json({ error: "Internal server error" });
  }
};

export default protectRoute;
