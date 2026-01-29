import type { Response, Request, NextFunction } from "express";
import authService from "../services/auth-services.js";
import jwtmiddleware from "../middlewares/jwt.js";
import { sendEmail } from "../services/email-services.js";
import { AppError } from "../utils/errors.js";

export const registerUserHanlder = async (
  req: Request,
  resp: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const { email, password, username, firstName, lastName, avatar } = req.body;

    // Basic validation
    if (!email || !password) {
      throw new AppError("Email and password is required!", 400);
    }

    if (password.length < 6) {
      throw new AppError("Password must be at least 6 characters long", 400);
    }

    // Create user using auth service
    const user = await authService.createUser(
      email,
      password,
      username,
      firstName,
      lastName,
      avatar,
    );

    resp.status(201).json({
      message: "User registered successfully!",
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    next(error);
  }
};

export const loginUserHandler = async (
  req: Request,
  resp: Response,
  next: NextFunction,
) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      throw new AppError("Email and password is required", 400);
    }

    // Find user by email
    const user = await authService.findUserByEmail(email);

    if (!user) {
      throw new AppError(`Invalid email or password`, 401);
    }

    // Verify password
    const isPasswordValid = await authService.verifyPassword(
      password,
      user.password,
    );

    if (!isPasswordValid) {
      throw new AppError("Invalid password or email", 401);
    }

    // Check if user is active
    if (!user.isActive) {
      throw new AppError("Account is deactivated", 401);
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
      userAgent,
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
    next(error);
  }
};

export const refreshTokenHanlder = async (
  req: Request,
  resp: Response,
  next: NextFunction,
) => {
  try {
    const oldRefreshToken =
      req.body.refreshToken ||
      (req.headers.authorization?.startsWith("Bearer ")
        ? req.headers.authorization.substring(7)
        : null);

    if (!oldRefreshToken) {
      throw new AppError("Refresh token is required", 400);
    }

    // Verify the refresh token (will throw on invalid/expired)
    jwtmiddleware.verifyRefreshToken(oldRefreshToken);

    const session = await authService.findSessionByToken(oldRefreshToken);
    if (!session) {
      throw new AppError("Invalid refresh token", 401);
    }

    if (session.expiresAt < new Date()) {
      await authService.deleteSession(oldRefreshToken);
      throw new AppError("Refresh token has expired", 401);
    }

    if (!session.user.isActive) {
      throw new AppError("User account is deactivated", 401);
    }

    const userRoles = session.user.userRoles.map((ur) => ur.role.name) || [];

    const { accessToken, refreshToken } = jwtmiddleware.generateTokenPair({
      id: session.user.id,
      email: session.user.email,
      roles: userRoles,
    });

    const ipAddress =
      req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    const userAgent = req.get("User-Agent");

    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

    await authService.deleteSession(oldRefreshToken);
    await authService.createSession(
      session.user.id,
      refreshToken,
      refreshTokenExpiry,
      ipAddress,
      userAgent,
    );

    resp.status(200).json({
      message: "Tokens refreshed successfully",
      tokens: {
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    next(error);
  }
};

export const logoutUserHandler = async (
  req: Request,
  resp: Response,
  next: NextFunction,
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
    next(error);
  }
};

export const requestEmailVerificationHandler = async (
  req: Request,
  resp: Response,
  next: NextFunction,
) => {
  try {
    const { email } = req.body;

    if (!email) throw new AppError("Email is required!", 400);
    const user = await authService.findUserByEmail(email);
    if (!user) {
      // don’t reveal existence
      return resp
        .status(200)
        .json({ message: "If the account exists, an email was sent." });
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
    next(error);
  }
};

export const confirmEmailVerificationHandler = async (
  req: Request,
  resp: Response,
  next: NextFunction,
) => {
  try {
    const token = String(req.query.token || "");
    if (!token) throw new AppError("Token is required!", 400);

    await authService.verifyEmailToken(token);
    return resp.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    next(error);
  }
};

export const forgotPasswordHandler = async (
  req: Request,
  resp: Response,
  next: NextFunction,
) => {
  try {
    const { email } = req.body;
    if (!email) throw new AppError("Email is required", 400);

    const user = await authService.findUserByEmail(email);

    // Always return 200 to avoid user enumeration
    if (!user) {
      return resp
        .status(200)
        .json({ message: "If the account exists, an email was sent." });
    }

    const { token } = await authService.createPasswordReset(user.id);

    const appUrl = process.env.APP_URL || "http://localhost:3002";
    // Usually this link should point to your frontend page:
    // e.g. `${FRONTEND_URL}/reset-password?token=...`
    const link = `${appUrl}/api/v1/auth/password/reset?token=${token}`;

    await sendEmail({
      to: user.email,
      subject: "Reset your password",
      html: `<p>Reset your password using this link:</p><p><a href="${link}">${link}</a></p>`,
    });

    return resp
      .status(200)
      .json({ message: "If the account exists, an email was sent." });
  } catch (error) {
    next(error);
  }
};

export const resetPasswordFormHandler = async (
  req: Request,
  resp: Response,
) => {
  const token = String(req.query.token || "");
  if (!token) return resp.status(400).send("Token is required");

  // Minimal HTML page served by backend
  resp.setHeader("Content-Type", "text/html; charset=utf-8");
  return resp.status(200).send(`
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Reset password</title>
              <style>
          body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
          form { margin-top: 20px; }
          label { display: block; margin-bottom: 5px; font-weight: bold; }
          input[type="password"] { width: 100%; padding: 8px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px; }
          button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
          button:hover { background-color: #0056b3; }
          .error { color: red; margin-top: 10px; }
        </style>

      </head>
     <body>
        <h2>Reset your password</h2>
        <form method="POST" action="/api/v1/auth/password/reset">
          <input type="hidden" name="token" value="${token}" />
          <label for="newPassword">New password (minimum 6 characters):</label>
          <input
            id="newPassword"
            type="password"
            name="newPassword"
            minlength="6"
            required
            autocomplete="new-password"
          />
          <button type="submit">Reset password</button>
        </form>
      </body>
    </html>
  `);
};

export const resetPasswordHandler = async (
  req: Request,
  resp: Response,
  next: NextFunction,
) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      throw new AppError("Token and new password are required", 400);
    }
    if (newPassword.length < 6) {
      throw new AppError("Password must be at least 6 character long", 400);
    }

    await authService.resetPasswordWithToken(token, newPassword);
    return resp.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    next(error);
  }
};
