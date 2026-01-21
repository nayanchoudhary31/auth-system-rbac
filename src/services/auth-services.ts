import bcrypt from "bcrypt";
import prisma from "../config/db.js";
import { generateToken } from "../utils/token.js";

class AuthService {
  // Hash password using bcrypt
  async hashPassword(password: string): Promise<string> {
    const saltRounds = 12; // Higher salt rounds for better security
    return await bcrypt.hash(password, saltRounds);
  }

  // Verify password against hash
  async verifyPassword(
    password: string,
    hashedPassword: string
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }

  // udpate user's last login timestamp
  async updateLastLogin(userId: string): Promise<void> {
    await prisma.user.update({
      where: { id: userId },
      data: { lastLoginAt: new Date() },
    });
  }

  // Create new user with hashed password
  async createUser(
    email: string,
    password: string,
    username?: string,
    firstName?: string,
    lastName?: string,
    avatar?: string
  ) {
    try {
      // Check if user already exists
      const existingUser = await prisma.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        throw new Error("User with this email already exists");
      }

      // Check if username is taken (if provided)
      if (username) {
        const existingUsername = await prisma.user.findUnique({
          where: { username },
        });

        if (existingUsername) {
          throw new Error("Username is already taken");
        }
      }

      // Hash the password
      const hashedPassword = await this.hashPassword(password);

      // Create user in database
      const user = await prisma.user.create({
        data: {
          email,
          username: username || null,
          firstName: firstName || null,
          lastName: lastName || null,
          avatar: avatar || null,
          password: hashedPassword,
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
          createdAt: true,
          // Don't return password in response
        },
      });

      try { 
        await this.assignDefaultRole(user.id, "USER")
      } catch (roleError) {
        console.error(`Failed to assign default role: ${roleError}`)
      }

      return user;
    } catch (error) {
      throw error;
    }
  }

  // Create an new session for user
  async createSession(
    userId: string,
    token: string,
    expiresAt: Date,
    ipAddress?: string,
    userAgent?: string
  ) {
    return await prisma.session.create({
      data: {
        userId,
        token,
        expiresAt,
        ipAddress: ipAddress || null,
        userAgent: userAgent || null,
      },
    });
  }

  // Find user by email for login
  async findUserByEmail(email: string) {
    return await prisma.user.findUnique({
      where: { email },
      include: {
        userRoles: {
          include: {
            role: {
              include: {
                rolePermissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });
  }

  // Find user by ID
  async findUserById(id: string) {
    return await prisma.user.findUnique({
      where: { id },
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
        userRoles: {
          include: {
            role: {
              include: {
                rolePermissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
        profile: true,
      },
    });
  }

  // Find session by token
  async findSessionByToken(token: string) {
    return await prisma.session.findUnique({
      where: { token },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            isActive: true,
            userRoles: {
              include: {
                role: true,
              },
            },
          },
        },
      },
    });
  }

  // Delete session for logout
  async deleteSession(token: string): Promise<void> {
    await prisma.session.delete({
      where: { token },
    });
  }

  // Delete all sessions for a user (for security purpose)
  async deleteAllUserSessions(userId: string): Promise<void> {
    await prisma.session.deleteMany({
      where: { userId },
    });
  }

  // clean up expired sessions
  async cleanUpExpiredSessions(): Promise<void> {
    await prisma.session.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
  }

  async assignDefaultRole(userId: string, roleName: string = "USER") {
    // Find the role by name

    const role = await prisma.role.findUnique({
      where: { name: roleName }
    })

    if (!role) {
      throw new Error(`Role ${roleName} not found. Please run the seed script first`)
    }

    // Check is this user already has this role
    const existingUserRole = await prisma.userRole.findUnique({
      where: {
        userId_roleId: {
          userId,
          roleId: role.id
        }
      }
    })

    // Only assign if not already assigned
    if (!existingUserRole) {
      await prisma.userRole.create({
        data: {
          userId,
          roleId: role.id,
          // assignedBy can be null for system-assigned roles
        },
      });
    }

    return role;
  }

  // Email verification creation
  async createEmailVerification(userId: string) {
    const token = generateToken();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60); // 1 hour

    await prisma.emailVerification.create({
      data: { userId, token, expiresAt },
    });

    return { token, expiresAt };
  }

  // verify the email
  async verifyEmailToken(token: string) {
    const record = await prisma.emailVerification.findUnique({ where: { token } });
    if (!record) throw new Error("Invalid verification token");
    if (record.verified) throw new Error("Token already used");
    if (record.expiresAt < new Date()) throw new Error("Token expired");

    await prisma.$transaction([
      prisma.emailVerification.update({
        where: { token },
        data: { verified: true },
      }),
      prisma.user.update({
        where: { id: record.userId },
        data: { isVerified: true },
      }),
    ]);

    return true;
  }

  // Password reset request
  async createPasswordReset(userId: string) {
    const token = generateToken();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 30); // 30 min

    await prisma.passwordReset.create({
      data: { userId, token, expiresAt },
    });

    return { token, expiresAt };
  }

  // Reset password with token
  async resetPasswordWithToken(token: string, newPassword: string) {
    const record = await prisma.passwordReset.findUnique({ where: { token } });
    if (!record) throw new Error("Invalid reset token");
    if (record.used) throw new Error("Token already used");
    if (record.expiresAt < new Date()) throw new Error("Token expired");

    const hashed = await this.hashPassword(newPassword);

    await prisma.$transaction([
      prisma.passwordReset.update({
        where: { token },
        data: { used: true },
      }),
      prisma.user.update({
        where: { id: record.userId },
        data: { password: hashed },
      }),
      prisma.session.deleteMany({
        where: { userId: record.userId }, // revoke all sessions after reset
      }),
    ]);

    return true;
  }
}

export default new AuthService();
