import jwt, { type Secret, type SignOptions } from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";
import authService from "../services/auth-services.js";

/**
 * JWT Middleware Class
 *
 * This class handles all JWT-related operations including:
 * - Token generation (access & refresh tokens)
 * - Token verification
 * - Authentication middleware
 * - Authorization middleware
 */
class JWTMiddleware {
  // Private properties for JWT configuration
  private readonly accessTokenSecret: Secret;
  private readonly refreshTokenSecret: Secret;
  private readonly accessTokenExpiry: NonNullable<SignOptions["expiresIn"]>;
  private readonly refreshTokenExpiry: NonNullable<SignOptions["expiresIn"]>;

  constructor() {
    this.accessTokenSecret = (process.env.JWT_ACCESS_SECRET ||
      "your-access-secret-key") as Secret;
    this.refreshTokenSecret = (process.env.JWT_REFRESH_SECRET ||
      "your-refresh-secret-key") as Secret;
    this.accessTokenExpiry = (process.env.JWT_ACCESS_EXPIRY ||
      "15M") as NonNullable<SignOptions["expiresIn"]>;
    this.refreshTokenExpiry = (process.env.JWT_REFRESH_EXPIRY ||
      "7D") as NonNullable<SignOptions["expiresIn"]>;
  }

  /**
   * Generate Access Token
   *
   * Access tokens are short-lived tokens (15 minutes) that contain user information
   * and are used for API authentication. They include:
   * - User ID, email, username
   * - User roles for authorization
   * - Short expiration time for security
   */
  generateAccessToken(payload: {
    id: string;
    email: string;
    username?: string | undefined;
    roles: string[];
  }): string {
    const options: SignOptions = {
      expiresIn: this.accessTokenExpiry,
      issuer: "auth-system",
      audience: "auth-system-users",
    };
    return jwt.sign(payload, this.accessTokenSecret, options);
  }

  /**
   * Generate Refresh Token
   *
   * Refresh tokens are long-lived tokens (7 days) used to generate new access tokens
   * without requiring user to login again. They contain minimal information:
   * - Only user ID and email
   * - Longer expiration time
   * - Used only for token refresh, not for API access
   */
  generateRefreshToken(payload: { id: string; email: string }): string {
    const options: SignOptions = {
      expiresIn: this.refreshTokenExpiry,
      issuer: "auth-system",
      audience: "auth-system-users",
    };
    return jwt.sign(payload, this.refreshTokenSecret, options);
  }

  /**
   * Verify Access Token
   *
   * This method verifies if an access token is valid by:
   * - Checking the signature using the secret
   * - Verifying expiration time
   * - Checking issuer and audience
   * - Returning the decoded payload if valid
   */
  verifyAccessToken(token: string): any {
    try {
      return jwt.verify(token, this.accessTokenSecret, {
        issuer: "auth-system",
        audience: "auth-system-users",
      });
    } catch (error) {
      throw new Error("Invalid or expired access token");
    }
  }

  /**
   * Verify Refresh Token
   *
   * Similar to access token verification but uses refresh token secret
   * and is used specifically for token refresh operations
   */
  verifyRefreshToken(token: string): any {
    try {
      return jwt.verify(token, this.refreshTokenSecret, {
        issuer: "auth-system",
        audience: "auth-system-users",
      });
    } catch (error) {
      throw new Error("Invalid or expired refresh token");
    }
  }

  /**
   * Authentication Middleware
   *
   * This is the main middleware that protects routes requiring authentication.
   * It:
   * 1. Extracts the Bearer token from Authorization header
   * 2. Verifies the token
   * 3. Fetches user from database to ensure they still exist and are active
   * 4. Attaches user information to the request object
   * 5. Calls next() to continue to the protected route
   */
  authenticate = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      // Step 1: Extract token from Authorization header
      const authHeader = req.headers.authorization;

      // Check if Authorization header exists and follows "Bearer <token>" format
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({ error: "Access token required" });
        return;
      }

      // Extract the actual token (remove "Bearer " prefix)
      const token = authHeader.substring(7);

      // Step 2: Verify the token
      const decoded = this.verifyAccessToken(token);

      // Step 3: Get user from database to ensure they still exist and are active
      // This is important because:
      // - User might have been deleted after token was issued
      // - User might have been deactivated
      // - User roles might have changed
      const user = await authService.findUserById(decoded.id);

      if (!user || !user.isActive) {
        res.status(401).json({ error: "User not found or inactive" });
        return;
      }

      // Step 4: Extract roles from user data
      const roles = user.userRoles?.map((ur) => ur.role.name) || [];

      // Step 5: Attach user info to request object
      // This makes user information available in the route handler
      req.user = {
        id: user.id,
        email: user.email,
        username: user.username || undefined,
        roles,
      };

      // Step 6: Continue to the next middleware/route handler
      next();
    } catch (error) {
      console.error("Authentication error:", error);
      res.status(401).json({
        error: error instanceof Error ? error.message : "Authentication failed",
      });
    }
  };

  /**
   * Role-based Authorization Middleware
   *
   * This middleware checks if the authenticated user has the required roles
   * to access a specific resource. It's used after the authenticate middleware.
   *
   * Usage: jwtMiddleware.authorize(['ADMIN', 'MODERATOR'])
   */
  authorize = (requiredRoles: string[]) => {
    return (req: Request, res: Response, next: NextFunction): void => {
      // First check if user is authenticated
      if (!req.user) {
        res.status(401).json({ error: "Authentication required" });
        return;
      }

      // Check if user has any of the required roles
      const hasRequiredRole = requiredRoles.some((role) =>
        req.user!.roles.includes(role)
      );

      if (!hasRequiredRole) {
        res.status(403).json({
          error: "Insufficient permissions",
          required: requiredRoles,
          userRoles: req.user.roles,
        });
        return;
      }

      next();
    };
  };

  /**
   * Optional Authentication Middleware
   *
   * This middleware doesn't fail if no token is provided.
   * It's useful for routes that work differently for authenticated vs anonymous users.
   *
   * Example: A blog post that shows edit buttons only for authenticated users
   */
  optionalAuth = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;

      // If no token provided, continue without user info
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        next();
        return;
      }

      // If token is provided, try to authenticate
      const token = authHeader.substring(7);
      const decoded = this.verifyAccessToken(token);

      const user = await authService.findUserById(decoded.id);

      // If user exists and is active, attach to request
      if (user && user.isActive) {
        const roles = user.userRoles?.map((ur) => ur.role.name) || [];
        req.user = {
          id: user.id,
          email: user.email,
          username: user.username || undefined,
          roles,
        };
      }

      // Always continue, even if authentication failed
      next();
    } catch (error) {
      // Continue without user info if token is invalid
      next();
    }
  };

  /**
   * Generate Token Pair
   *
   * This method generates both access and refresh tokens for a user.
   * It's typically called after successful login or registration.
   */
  generateTokenPair(user: {
    id: string;
    email: string;
    username?: string;
    roles: string[];
  }) {
    const accessToken = this.generateAccessToken({
      id: user.id,
      email: user.email,
      username: user.username,
      roles: user.roles,
    });

    const refreshToken = this.generateRefreshToken({
      id: user.id,
      email: user.email,
    });

    return { accessToken, refreshToken };
  }
}

// Export a singleton instance
export default new JWTMiddleware();
