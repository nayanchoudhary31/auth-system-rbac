import type { Request, Response, NextFunction } from "express";
import prisma from "../config/db.js";

export const getAllUserHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const offset = (pageNum - 1) * limitNum;

    // Build where clause for search
    const whereClause = search
      ? {
          OR: [
            {
              email: {
                contains: search as string,
                mode: "insensitive" as const,
              },
            },
            {
              username: {
                contains: search as string,
                mode: "insensitive" as const,
              },
            },
            {
              firstName: {
                contains: search as string,
                mode: "insensitive" as const,
              },
            },
            {
              lastName: {
                contains: search as string,
                mode: "insensitive" as const,
              },
            },
          ],
        }
      : {};

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where: whereClause,
        select: {
          id: true,
          email: true,
          username: true,
          firstName: true,
          lastName: true,
          isVerified: true,
          isActive: true,
          lastLoginAt: true,
          createdAt: true,
          updatedAt: true,
          userRoles: {
            include: {
              role: true,
            },
          },
        },
        skip: offset,
        take: limitNum,
        orderBy: { createdAt: "desc" },
      }),
      prisma.user.count({ where: whereClause }),
    ]);

    resp.status(200).json({
      message: "Users retrieved successfully",
      users: users.map((user) => ({
        ...user,
        roles: user.userRoles.map((ur) => ur.role.name),
      })),
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum),
      },
    });
  } catch (error) {
    console.error("Get all users error:", error);
    resp.status(500).json({
      error: "Failed to retrieve users",
    });
  }
};

// ===== ROLE MANAGEMENT =====

export const getAllRolesHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const roles = await prisma.role.findMany({
      include: {
        _count: {
          select: {
            userRoles: true,
            rolePermissions: true,
          },
        },
      },
      orderBy: { name: "asc" },
    });

    resp.status(200).json({
      message: "Roles retrieved successfully",
      roles,
    });
  } catch (error) {
    console.error("Get all roles error:", error);
    resp.status(500).json({
      error: "Failed to retrieve roles",
    });
  }
};

export const createRoleHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      resp.status(400).json({
        error: "Role name is required",
      });
      return;
    }

    // Check if role already exists
    const existingRole = await prisma.role.findUnique({
      where: { name: name.toUpperCase() },
    });

    if (existingRole) {
      resp.status(400).json({
        error: "Role with this name already exists",
      });
      return;
    }

    const role = await prisma.role.create({
      data: {
        name: name.toUpperCase(),
        description,
      },
    });

    resp.status(201).json({
      message: "Role created successfully",
      role,
    });
  } catch (error) {
    console.error("Create role error:", error);
    resp.status(500).json({
      error: "Failed to create role",
    });
  }
};

export const updateRoleHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { id } = req.params;
    const { name, description } = req.body;

    if (!id) {
      resp.status(400).json({
        error: "Role ID is required",
      });
      return;
    }

    // Check if role exists
    const existingRole = await prisma.role.findUnique({
      where: { id },
    });

    if (!existingRole) {
      resp.status(404).json({
        error: "Role not found",
      });
      return;
    }

    // Check if new name conflicts with existing role
    if (name && name.toUpperCase() !== existingRole.name) {
      const conflictingRole = await prisma.role.findUnique({
        where: { name: name.toUpperCase() },
      });

      if (conflictingRole) {
        resp.status(400).json({
          error: "Role with this name already exists",
        });
        return;
      }
    }

    const updatedRole = await prisma.role.update({
      where: { id },
      data: {
        ...(name && { name: name.toUpperCase() }),
        ...(description !== undefined && { description }),
      },
    });

    resp.status(200).json({
      message: "Role updated successfully",
      role: updatedRole,
    });
  } catch (error) {
    console.error("Update role error:", error);
    resp.status(500).json({
      error: "Failed to update role",
    });
  }
};

export const deleteRoleHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { id } = req.params;

    if (!id) {
      resp.status(400).json({
        error: "Role ID is required",
      });
      return;
    }

    // Check if role exists
    const role = await prisma.role.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            userRoles: true,
          },
        },
      },
    });

    if (!role) {
      resp.status(404).json({
        error: "Role not found",
      });
      return;
    }

    // Prevent deletion of roles that are assigned to users
    if (role._count.userRoles > 0) {
      resp.status(400).json({
        error: "Cannot delete role that is assigned to users",
      });
      return;
    }

    await prisma.role.delete({
      where: { id },
    });

    resp.status(200).json({
      message: "Role deleted successfully",
    });
  } catch (error) {
    console.error("Delete role error:", error);
    resp.status(500).json({
      error: "Failed to delete role",
    });
  }
};

// ===== PERMISSION MANAGEMENT =====

export const getAllPermissionsHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const permissions = await prisma.permission.findMany({
      include: {
        _count: {
          select: {
            rolePermissions: true,
          },
        },
      },
      orderBy: [{ resource: "asc" }, { action: "asc" }],
    });

    resp.status(200).json({
      message: "Permissions retrieved successfully",
      permissions,
    });
  } catch (error) {
    console.error("Get all permissions error:", error);
    resp.status(500).json({
      error: "Failed to retrieve permissions",
    });
  }
};

export const createPermissionHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { name, description, resource, action } = req.body;

    if (!name || !resource || !action) {
      resp.status(400).json({
        error: "Name, resource, and action are required",
      });
      return;
    }

    // Check if permission already exists
    const existingPermission = await prisma.permission.findUnique({
      where: { name },
    });

    if (existingPermission) {
      resp.status(400).json({
        error: "Permission with this name already exists",
      });
      return;
    }

    const permission = await prisma.permission.create({
      data: {
        name,
        description,
        resource,
        action,
      },
    });

    resp.status(201).json({
      message: "Permission created successfully",
      permission,
    });
  } catch (error) {
    console.error("Create permission error:", error);
    resp.status(500).json({
      error: "Failed to create permission",
    });
  }
};

// ===== ROLE-PERMISSION MANAGEMENT =====

export const getRolePermissionsHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { roleId } = req.params;

    if (!roleId) {
      resp.status(400).json({
        error: "Role ID is required",
      });
      return;
    }

    const role = await prisma.role.findUnique({
      where: { id: roleId },
      include: {
        rolePermissions: {
          include: {
            permission: true,
          },
        },
      },
    });

    if (!role) {
      resp.status(404).json({
        error: "Role not found",
      });
      return;
    }

    resp.status(200).json({
      message: "Role permissions retrieved successfully",
      role: {
        id: role.id,
        name: role.name,
        description: role.description,
        permissions: role.rolePermissions.map((rp) => rp.permission),
      },
    });
  } catch (error) {
    console.error("Get role permissions error:", error);
    resp.status(500).json({
      error: "Failed to retrieve role permissions",
    });
  }
};

export const assignPermissionToRoleHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { roleId } = req.params;
    const { permissionId } = req.body;

    if (!roleId || !permissionId) {
      resp.status(400).json({
        error: "Role ID and Permission ID are required",
      });
      return;
    }

    // Check if role exists
    const role = await prisma.role.findUnique({
      where: { id: roleId },
    });

    if (!role) {
      resp.status(404).json({
        error: "Role not found",
      });
      return;
    }

    // Check if permission exists
    const permission = await prisma.permission.findUnique({
      where: { id: permissionId },
    });

    if (!permission) {
      resp.status(404).json({
        error: "Permission not found",
      });
      return;
    }

    // Check if permission is already assigned to role
    const existingAssignment = await prisma.rolePermission.findUnique({
      where: {
        roleId_permissionId: {
          roleId,
          permissionId,
        },
      },
    });

    if (existingAssignment) {
      resp.status(400).json({
        error: "Permission is already assigned to this role",
      });
      return;
    }

    const rolePermission = await prisma.rolePermission.create({
      data: {
        roleId,
        permissionId,
      },
      include: {
        permission: true,
      },
    });

    resp.status(201).json({
      message: "Permission assigned to role successfully",
      rolePermission,
    });
  } catch (error) {
    console.error("Assign permission to role error:", error);
    resp.status(500).json({
      error: "Failed to assign permission to role",
    });
  }
};

export const removePermissionFromRoleHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { roleId, permissionId } = req.params;

    if (!roleId || !permissionId) {
      resp.status(400).json({
        error: "Role ID and Permission ID are required",
      });
      return;
    }

    const rolePermission = await prisma.rolePermission.findUnique({
      where: {
        roleId_permissionId: {
          roleId,
          permissionId,
        },
      },
    });

    if (!rolePermission) {
      resp.status(404).json({
        error: "Permission assignment not found",
      });
      return;
    }

    await prisma.rolePermission.delete({
      where: {
        roleId_permissionId: {
          roleId,
          permissionId,
        },
      },
    });

    resp.status(200).json({
      message: "Permission removed from role successfully",
    });
  } catch (error) {
    console.error("Remove permission from role error:", error);
    resp.status(500).json({
      error: "Failed to remove permission from role",
    });
  }
};

// ===== USER ROLE MANAGEMENT =====

export const getUserRolesHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { id } = req.params;

    if (!id) {
      resp.status(400).json({
        error: "User ID is required",
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id },
      include: {
        userRoles: {
          include: {
            role: true,
          },
        },
      },
    });

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    resp.status(200).json({
      message: "User roles retrieved successfully",
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        roles: user.userRoles.map((ur) => ({
          id: ur.role.id,
          name: ur.role.name,
          description: ur.role.description,
          assignedAt: ur.assignedAt,
          assignedBy: ur.assignedBy,
        })),
      },
    });
  } catch (error) {
    console.error("Get user roles error:", error);
    resp.status(500).json({
      error: "Failed to retrieve user roles",
    });
  }
};

export const updateUserRoleHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { id } = req.params;
    const { roleId } = req.body;

    if (!id) {
      resp.status(400).json({
        error: "User ID is required", // ✅ Fixed the error message
      });
      return;
    }

    if (!roleId) {
      resp.status(400).json({
        error: "Role ID is required",
      });
      return;
    }

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id },
      include: { userRoles: true },
    });

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    // Check if role exists
    const role = await prisma.role.findUnique({
      where: { id: roleId },
    });

    if (!role) {
      resp.status(404).json({
        error: "Role not found",
      });
      return;
    }

    // Check if user already has this role
    const existingUserRole = await prisma.userRole.findUnique({
      where: {
        userId_roleId: {
          userId: id,
          roleId: roleId,
        },
      },
    });

    if (existingUserRole) {
      resp.status(400).json({
        error: "User already has this role",
      });
      return;
    }

    // Add role to user
    const userRole = await prisma.userRole.create({
      data: {
        userId: id,
        roleId: roleId,
        assignedBy: req.user?.id || null, // ✅ Convert undefined to null
      },
      include: {
        role: true,
      },
    });

    resp.status(200).json({
      message: "User role updated successfully",
      userRole: {
        id: userRole.id,
        role: userRole.role.name,
        assignedAt: userRole.assignedAt,
      },
    });
  } catch (error) {
    console.error("Update user role error:", error);
    resp.status(500).json({
      error: "Failed to update user role",
    });
  }
};

export const removeUserRoleHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { id, roleId } = req.params;

    if (!id || !roleId) {
      resp.status(400).json({
        error: "User ID and Role ID are required",
      });
      return;
    }

    const userRole = await prisma.userRole.findUnique({
      where: {
        userId_roleId: {
          userId: id,
          roleId: roleId,
        },
      },
      include: {
        role: true,
      },
    });

    if (!userRole) {
      resp.status(404).json({
        error: "User role assignment not found",
      });
      return;
    }

    await prisma.userRole.delete({
      where: {
        userId_roleId: {
          userId: id,
          roleId: roleId,
        },
      },
    });

    resp.status(200).json({
      message: "User role removed successfully",
    });
  } catch (error) {
    console.error("Remove user role error:", error);
    resp.status(500).json({
      error: "Failed to remove user role",
    });
  }
};

// ===== ENHANCED USER MANAGEMENT =====

export const toggleUserStatusHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;

    if (!id) {
      resp.status(400).json({
        error: "User ID is required",
      });
      return;
    }

    if (typeof isActive !== "boolean") {
      resp.status(400).json({
        error: "isActive must be a boolean value",
      });
      return;
    }

    // Prevent admin from deactivating themselves
    if (id === req.user?.id && !isActive) {
      resp.status(400).json({
        error: "Cannot deactivate your own account",
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    const updatedUser = await prisma.user.update({
      where: { id },
      data: { isActive },
    });

    resp.status(200).json({
      message: `User ${isActive ? "activated" : "deactivated"} successfully`,
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        isActive: updatedUser.isActive,
      },
    });
  } catch (error) {
    console.error("Toggle user status error:", error);
    resp.status(500).json({
      error: "Failed to update user status",
    });
  }
};

export const getUserSessionsHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { id } = req.params;

    if (!id) {
      resp.status(400).json({
        error: "User ID is required",
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    const sessions = await prisma.session.findMany({
      where: { userId: id },
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

    // Sanitize tokens
    const sanitizedSessions = sessions.map((session) => ({
      ...session,
      token: `...${session.token.slice(-8)}`,
    }));

    resp.status(200).json({
      message: "User sessions retrieved successfully",
      sessions: sanitizedSessions,
    });
  } catch (error) {
    console.error("Get user sessions error:", error);
    resp.status(500).json({
      error: "Failed to retrieve user sessions",
    });
  }
};

export const revokeUserSessionsHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { id } = req.params;

    if (!id) {
      resp.status(400).json({
        error: "User ID is required",
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    await prisma.session.deleteMany({
      where: { userId: id },
    });

    resp.status(200).json({
      message: "User sessions revoked successfully",
    });
  } catch (error) {
    console.error("Revoke user sessions error:", error);
    resp.status(500).json({
      error: "Failed to revoke user sessions",
    });
  }
};

export const deleteUserHandler = async (
  req: Request,
  resp: Response,
  _next: NextFunction
) => {
  try {
    const { id } = req.params;

    if (!id) {
      resp.status(400).json({
        error: "User ID is required",
      });
      return;
    }

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      resp.status(404).json({
        error: "User not found",
      });
      return;
    }

    // Prevent admin from deleting themselves
    if (id === req.user?.id) {
      resp.status(400).json({
        error: "Cannot delete your own account",
      });
      return;
    }

    // Delete user (cascade will handle related records)
    await prisma.user.delete({
      where: { id },
    });

    resp.status(200).json({
      message: "User deleted successfully",
    });
  } catch (error) {
    console.error("Delete user error:", error);
    resp.status(500).json({
      error: "Failed to delete user",
    });
  }
};
