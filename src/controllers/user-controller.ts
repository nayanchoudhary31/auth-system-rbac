import type { Response, Request, NextFunction } from "express";
import authService from "../services/auth-services.js";
import prisma from "../config/db.js";

export const getUserProfileHandlder = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    // User info is available from JWT middleware
    const userId = req.user?.id;

    if (!userId) {
      resp.status(401).json({
        error: "User not authenticated",
      });
      return;
    }

    const user = await authService.findUserById(userId);

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    resp.status(200).json({
      message: "Profile retrieved successfully",
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        avatar: user.avatar,
        isVerified: user.isVerified,
        isActive: user.isActive,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        roles: user.userRoles?.map((ur) => ur.role.name) || [],
        profile: user.profile,
      },
    });
  } catch (error) {
    console.error("Get profile error:", error);
    resp.status(500).json({
      error: "Failed to retrieve profile",
    });
  }
};

export const updateUserHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const userId = req.user?.id;
    const { firstName, lastName, username } = req.body;

    if (!userId) {
      resp.status(401).json({
        error: "User not authenticated",
      });
      return;
    }

    // Validate input
    if (!firstName && !lastName && !username) {
      resp.status(400).json({
        error: "At least one field (firstName, lastName, username) is required",
      });
      return;
    }

    // Check if username is already taken by another user
    if (username) {
      const existingUser = await prisma.user.findFirst({
        where: {
          username,
          id: { not: userId }, // Exclude current user
        },
      });

      if (existingUser) {
        resp.status(400).json({
          error: "Username is already taken",
        });
        return;
      }
    }

    // Update user
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        ...(firstName && { firstName }),
        ...(lastName && { lastName }),
        ...(username && { username }),
      },
      select: {
        id: true,
        email: true,
        username: true,
        firstName: true,
        lastName: true,
        avatar: true,
        isVerified: true,
        isActive: true,
        lastLoginAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    resp.status(200).json({
      message: "Profile updated successfully",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Update user error:", error);
    resp.status(500).json({
      error: "Failed to update profile",
    });
  }
};

export const updateUserProfileHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const userId = req.user?.id;
    const {
      bio,
      phone,
      address,
      city,
      country,
      timezone,
      language,
      website,
      twitter,
      linkedin,
      github,
      emailNotifications,
      smsNotifications,
    } = req.body;

    if (!userId) {
      resp.status(401).json({
        error: "User not authenticated",
      });
      return;
    }

    // Upsert user profile (create if doesn't exist, update if exists)
    const userProfile = await prisma.userProfile.upsert({
      where: { userId },
      update: {
        ...(bio !== undefined && { bio }),
        ...(phone !== undefined && { phone }),
        ...(address !== undefined && { address }),
        ...(city !== undefined && { city }),
        ...(country !== undefined && { country }),
        ...(timezone !== undefined && { timezone }),
        ...(language !== undefined && { language }),
        ...(website !== undefined && { website }),
        ...(twitter !== undefined && { twitter }),
        ...(linkedin !== undefined && { linkedin }),
        ...(github !== undefined && { github }),
        ...(emailNotifications !== undefined && { emailNotifications }),
        ...(smsNotifications !== undefined && { smsNotifications }),
      },
      create: {
        userId,
        bio,
        phone,
        address,
        city,
        country,
        timezone,
        language: language || "en",
        website,
        twitter,
        linkedin,
        github,
        emailNotifications:
          emailNotifications !== undefined ? emailNotifications : true,
        smsNotifications:
          smsNotifications !== undefined ? smsNotifications : false,
      },
    });

    resp.status(200).json({
      message: "Profile updated successfully",
      profile: userProfile,
    });
  } catch (error) {
    console.error("Update profile error:", error);
    resp.status(500).json({
      error: "Failed to update profile",
    });
  }
};

export const changePasswordHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const userId = req.user?.id;
    const { currentPassword, newPassword } = req.body;

    if (!userId) {
      resp.status(401).json({
        error: "User not authenticated",
      });
      return;
    }

    if (!currentPassword || !newPassword) {
      resp.status(400).json({
        error: "Current password and new password are required",
      });
      return;
    }

    if (newPassword.length < 6) {
      resp.status(400).json({
        error: "New password must be at least 6 characters long",
      });
      return;
    }

    // Get user with password
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, password: true },
    });

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    // Verify current password
    const isCurrentPasswordValid = await authService.verifyPassword(
      currentPassword,
      user.password
    );

    if (!isCurrentPasswordValid) {
      resp.status(400).json({
        error: "Current password is incorrect",
      });
      return;
    }

    // Hash new password
    const hashedNewPassword = await authService.hashPassword(newPassword);

    // Update password
    await prisma.user.update({
      where: { id: userId },
      data: { password: hashedNewPassword },
    });

    // Revoke all sessions except current one (force re-login)
    const currentSessionToken = req.headers.authorization?.substring(7);
    if (currentSessionToken) {
      await authService.deleteAllUserSessions(userId);
    }

    resp.status(200).json({
      message: "Password changed successfully. Please log in again.",
    });
  } catch (error) {
    console.error("Change password error:", error);
    resp.status(500).json({
      error: "Failed to change password",
    });
  }
};

export const getUserSessionsHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      resp.status(401).json({
        error: "User not authenticated",
      });
      return;
    }

    const sessions = await prisma.session.findMany({
      where: { userId },
      select: {
        id: true,
        token: true,
        expiresAt: true,
        createdAt: true,
        ipAddress: true,
        userAgent: true,
      },
      orderBy: { createdAt: "desc" },
    });

    // Don't expose the full token, just show last 8 characters
    const sanitizedSessions = sessions.map((session) => ({
      ...session,
      token: `...${session.token.slice(-8)}`,
      isCurrent: session.token === req.headers.authorization?.substring(7),
    }));

    resp.status(200).json({
      message: "Sessions retrieved successfully",
      sessions: sanitizedSessions,
    });
  } catch (error) {
    console.error("Get sessions error:", error);
    resp.status(500).json({
      error: "Failed to retrieve sessions",
    });
  }
};

export const revokeSessionHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const userId = req.user?.id;
    const { sessionId } = req.params;

    if (!userId) {
      resp.status(401).json({
        error: "User not authenticated",
      });
      return;
    }
    if (!sessionId) {
      resp.status(400).json({
        error: "Session ID is required",
      });
      return;
    }

    // Find the session and verify it belongs to the user
    const session = await prisma.session.findFirst({
      where: {
        id: sessionId,
        userId,
      },
    });

    if (!session) {
      resp.status(404).json({
        error: "Session not found",
      });
      return;
    }

    // Delete the session
    await prisma.session.delete({
      where: { id: sessionId },
    });

    resp.status(200).json({
      message: "Session revoked successfully",
    });
  } catch (error) {
    console.error("Revoke session error:", error);
    resp.status(500).json({
      error: "Failed to revoke session",
    });
  }
};

export const revokeAllSessionsHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      resp.status(401).json({
        error: "User not authenticated",
      });
      return;
    }

    // Delete all sessions for the user
    await authService.deleteAllUserSessions(userId);

    resp.status(200).json({
      message: "All sessions revoked successfully. Please log in again.",
    });
  } catch (error) {
    console.error("Revoke all sessions error:", error);
    resp.status(500).json({
      error: "Failed to revoke sessions",
    });
  }
};

export const deactivateAccountHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const userId = req.user?.id;
    const { password } = req.body;

    if (!userId) {
      resp.status(401).json({
        error: "User not authenticated",
      });
      return;
    }

    if (!password) {
      resp.status(400).json({
        error: "Password is required to deactivate account",
      });
      return;
    }

    // Get user with password
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, password: true },
    });

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    // Verify password
    const isPasswordValid = await authService.verifyPassword(
      password,
      user.password
    );

    if (!isPasswordValid) {
      resp.status(400).json({
        error: "Password is incorrect",
      });
      return;
    }

    // Deactivate account
    await prisma.user.update({
      where: { id: userId },
      data: { isActive: false },
    });

    // Revoke all sessions
    await authService.deleteAllUserSessions(userId);

    resp.status(200).json({
      message: "Account deactivated successfully",
    });
  } catch (error) {
    console.error("Deactivate account error:", error);
    resp.status(500).json({
      error: "Failed to deactivate account",
    });
  }
};

export const deleteAccountHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const userId = req.user?.id;
    const { password } = req.body;

    if (!userId) {
      resp.status(401).json({
        error: "User not authenticated",
      });
      return;
    }

    if (!password) {
      resp.status(400).json({
        error: "Password is required to delete account",
      });
      return;
    }

    // Get user with password
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, password: true },
    });

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    // Verify password
    const isPasswordValid = await authService.verifyPassword(
      password,
      user.password
    );

    if (!isPasswordValid) {
      resp.status(400).json({
        error: "Password is incorrect",
      });
      return;
    }

    // Delete user (cascade will handle related records)
    await prisma.user.delete({
      where: { id: userId },
    });

    resp.status(200).json({
      message: "Account deleted successfully",
    });
  } catch (error) {
    console.error("Delete account error:", error);
    resp.status(500).json({
      error: "Failed to delete account",
    });
  }
};
