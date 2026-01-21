import type { Response, Request, NextFunction } from "express";
import authService from "../services/auth-services.js";
import jwtmiddleware from "../middlewares/jwt.js";
import { sendEmail } from "../services/email-services.js";

export const registerUserHanlder = async (
  req: Request,
  resp: Response,
  _next: NextFunction
): Promise<void> => {
  try {
    const { email, password, username, firstName, lastName, avatar } = req.body;

    // Basic validation
    if (!email || !password) {
      resp.status(400).json({
        error: "Email and password are required",
      });
      return;
    }

    if (password.length < 6) {
      resp.status(400).json({
        error: "Password must be at least 6 characters long",
      });
      return;
    }

    // Create user using auth service
    const user = await authService.createUser(
      email,
      password,
      username,
      firstName,
      lastName,
      avatar
    );

    resp.status(201).json({
      message: "User registered successfully!",
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        avatar: user.avatar
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    resp.status(400).json({
      error: error instanceof Error ? error.message : "Registration failed",
    });
  }
};

export const loginUserHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      resp.status(400).json({
        error: "Email and password are required",
      });
      return;
    }

    // Find user by email
    const user = await authService.findUserByEmail(email);

    if (!user) {
      resp.status(401).json({
        error: "Invalid email or password",
      });
      return;
    }

    // Verify password
    const isPasswordValid = await authService.verifyPassword(
      password,
      user.password
    );

    if (!isPasswordValid) {
      resp.status(401).json({
        error: "Invalid email or password",
      });
      return;
    }

    // Check if user is active
    if (!user.isActive) {
      resp.status(401).json({
        error: "Account is deactivated",
      });
      return;
    }

    const userRoles = user.userRoles.map((ur) => ur.role.name) || [];

    // Generate JWT tokens
    const { accessToken, refreshToken } = jwtmiddleware.generateTokenPair({
      id: user.id,
      email: user.email,
      roles: userRoles,
    });

    // Extract client information for session tracking
    const ipAddress =
      req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    const userAgent = req.get("User-Agent");

    // Calculate refresh token expiration (7 days from now)
    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

    // Create session record in database
    await authService.createSession(
      user.id,
      refreshToken,
      refreshTokenExpiry,
      ipAddress,
      userAgent
    );

    // Update lastLoginAt timestamp
    await authService.updateLastLogin(user.id);

    resp.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        roles: userRoles,
      },
      tokens: {
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    resp.status(500).json({
      error: "Login failed",
    });
  }
};

export const refreshTokenHanlder = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    // Extract refresh token from request body or Authorization header
    const oldRefreshToken =
      req.body.refreshToken ||
      (req.headers.authorization?.startsWith("Bearer ")
        ? req.headers.authorization.substring(7)
        : null);

    if (!oldRefreshToken) {
      resp.status(400).json({
        error: "Refresh token is required",
      });
      return;
    }

    // Verify the refresh token
    const decoded = jwtmiddleware.verifyRefreshToken(oldRefreshToken);

    // Find the session in database to ensure it exists and is valid
    const session = await authService.findSessionByToken(oldRefreshToken);

    if (!session) {
      resp.status(401).json({
        error: "Invalid refresh token",
      });
      return;
    }

    // Check if session has expired
    if (session.expiresAt < new Date()) {
      // Clean up expired session
      await authService.deleteSession(oldRefreshToken);
      resp.status(401).json({
        error: "Refresh token has expired",
      });
      return;
    }

    // Check if user is still active
    if (!session.user.isActive) {
      resp.status(401).json({
        error: "User account is deactivated",
      });
      return;
    }

    // Get user roles for new token
    const userRoles = session.user.userRoles.map((ur) => ur.role.name) || [];

    // Generate new token pair
    const { accessToken, refreshToken } = jwtmiddleware.generateTokenPair({
      id: session.user.id,
      email: session.user.email,
      roles: userRoles,
    });

    // Extract client information for session tracking
    const ipAddress =
      req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    const userAgent = req.get("User-Agent");

    // Calculate new refresh token expiration (7 days from now)
    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

    // Delete the old session
    await authService.deleteSession(oldRefreshToken);

    // Create new session with the new refresh token
    await authService.createSession(
      session.user.id,
      refreshToken,
      refreshTokenExpiry,
      ipAddress,
      userAgent
    );

    resp.status(200).json({
      message: "Tokens refreshed successfully",
      tokens: {
        accessToken,
        refreshToken: refreshToken,
      },
    });
  } catch (error) {
    console.error("Token refresh error:", error);

    // Handle specific JWT errors
    if (
      error instanceof Error &&
      error.message.includes("Invalid or expired refresh token")
    ) {
      resp.status(401).json({
        error: "Invalid or expired refresh token",
      });
      return;
    }

    resp.status(500).json({
      error: "Token refresh failed",
    });
  }
};

export const logoutUserHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    // Extract refresh token from request body or Authorization header
    const refreshToken =
      req.body.refreshToken ||
      (req.headers.authorization?.startsWith("Bearer ")
        ? req.headers.authorization.substring(7)
        : null);

    if (refreshToken) {
      // Delete the specific session
      await authService.deleteSession(refreshToken);
    }

    resp.status(200).json({
      message: "Logout successful",
    });
  } catch (error) {
    console.error("Logout error:", error);
    resp.status(500).json({
      error: "Logout failed",
    });
  }
};


export const requestEmailVerificationHandler = async (req: Request, resp: Response) => {
  try {
    const { email } = req.body;

    if (!email) return resp.status(400).json({ error: "Email is required!" })

    const user = await authService.findUserByEmail(email);
    if (!user) {
      // don’t reveal existence
      return resp.status(200).json({ message: "If the account exists, an email was sent." });
    }

    const { token } = await authService.createEmailVerification(user.id);

    const appUrl = process.env.APP_URL || "http://localhost:3002";
    const link = `${appUrl}/api/v1/auth/verify-email/confirm?token=${token}`;

    await sendEmail({
      to: user.email,
      subject: "Verify your email",
      html: `<p>Click to verify your email:</p><p><a href="${link}">${link}</a></p>`,
    });

    return resp.status(200).json({ message: "Verification email sent." });
  } catch (error) {
    return resp.status(500).json({ error: "Failed to send verification email" });
  }
}

export const confirmEmailVerificationHandler = async (req: Request, resp: Response) => {
  try {
    const token = String(req.query.token || "");
    if (!token) return resp.status(400).json({ error: "Token is required" });

    await authService.verifyEmailToken(token);
    return resp.status(200).json({ message: "Email verified successfully" });
  } catch (e) {
    return resp.status(400).json({ error: e instanceof Error ? e.message : "Verification failed" });
  }
};


export const forgotPasswordHandler = async (req: Request, resp: Response) => {
  try {
    const { email } = req.body;
    if (!email) return resp.status(400).json({ error: "Email is required" });

    const user = await authService.findUserByEmail(email);

    // Always return 200 to avoid user enumeration
    if (!user) {
      return resp.status(200).json({ message: "If the account exists, an email was sent." });
    }

    const { token } = await authService.createPasswordReset(user.id);

    const appUrl = process.env.APP_URL || "http://localhost:3001";
    // Usually this link should point to your frontend page:
    // e.g. `${FRONTEND_URL}/reset-password?token=...`
    const link = `${appUrl}/api/v1/auth/password/reset?token=${token}`;

    await sendEmail({
      to: user.email,
      subject: "Reset your password",
      html: `<p>Reset your password using this link:</p><p><a href="${link}">${link}</a></p>`,
    });

    return resp.status(200).json({ message: "If the account exists, an email was sent." });
  } catch (e) {
    return resp.status(500).json({ error: "Failed to process request" });
  }
};

export const resetPasswordFormHandler = async (req: Request, resp: Response) => {
  const token = String(req.query.token || "");
  if (!token) return resp.status(400).send("Token is required");

  // Minimal HTML page served by backend
  resp.setHeader("Content-Type", "text/html; charset=utf-8");
  return resp.status(200).send(`
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Reset password</title></head>
      <body>
        <h2>Reset password</h2>
        <form method="POST" action="/api/v1/auth/password/reset">
          <input type="hidden" name="token" value="${token}" />
          <label>New password</label><br/>
          <input type="password" name="newPassword" minlength="6" required />
          <button type="submit">Reset</button>
        </form>
      </body>
    </html>
  `);
};

export const resetPasswordHandler = async (req: Request, resp: Response) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      return resp.status(400).json({ error: "Token and newPassword are required" });
    }
    if (newPassword.length < 6) {
      return resp.status(400).json({ error: "Password must be at least 6 characters long" });
    }

    await authService.resetPasswordWithToken(token, newPassword);
    return resp.status(200).json({ message: "Password reset successfully" });
  } catch (e) {
    return resp.status(400).json({ error: e instanceof Error ? e.message : "Reset failed" });
  }
};