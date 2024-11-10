// auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';


declare global {
  namespace Express {
    interface Request {
      userId: string;
    }
  }
}


// Middleware to verify JWT token
const verifyToken = (req: Request, res: Response, next: NextFunction): void => {
  const token = req.cookies["auth_token"]; // Get the token from cookies

  if (!token) {
     res.status(401).json({ message: "Unauthorized: No token provided" });
     return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY as string) as JwtPayload;
    req.userId = decoded.userId; // Attach userId to the request object
    next(); // Proceed to the next middleware or route handler
  } catch (error) {
     res.status(401).json({ message: "Unauthorized: Invalid token" });
     return;
  }
};


export default verifyToken;