import bcrypt from "bcrypt";
import prisma from "../config/db.js";

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
}

export default new AuthService();
