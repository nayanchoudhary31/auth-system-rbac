import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  console.log("🌱 Starting database seeding...");

  // Create roles
  const roles = [
    {
      name: "ADMIN",
      description: "System administrator with full access",
    },
    {
      name: "USER",
      description: "Regular user with basic permissions",
    },
    {
      name: "MODERATOR",
      description: "User with moderation permissions",
    },
    {
      name: "MANAGER",
      description: "User with management permissions",
    },
  ];

  console.log("📝 Creating roles...");
  for (const roleData of roles) {
    const role = await prisma.role.upsert({
      where: { name: roleData.name },
      update: {},
      create: roleData,
    });
    console.log(`✅ Created/Updated role: ${role.name}`);
  }

  // Create permissions
  const permissions = [
    // User permissions
    {
      name: "users:read",
      description: "Read user information",
      resource: "users",
      action: "read",
    },
    {
      name: "users:create",
      description: "Create new users",
      resource: "users",
      action: "create",
    },
    {
      name: "users:update",
      description: "Update user information",
      resource: "users",
      action: "update",
    },
    {
      name: "users:delete",
      description: "Delete users",
      resource: "users",
      action: "delete",
    },

    // Profile permissions
    {
      name: "profile:read",
      description: "Read own profile",
      resource: "profile",
      action: "read",
    },
    {
      name: "profile:update",
      description: "Update own profile",
      resource: "profile",
      action: "update",
    },

    // Admin permissions
    {
      name: "admin:access",
      description: "Access admin panel",
      resource: "admin",
      action: "access",
    },
    {
      name: "admin:manage_roles",
      description: "Manage user roles",
      resource: "admin",
      action: "manage_roles",
    },
    {
      name: "admin:manage_users",
      description: "Manage all users",
      resource: "admin",
      action: "manage_users",
    },

    // Content permissions
    {
      name: "content:read",
      description: "Read content",
      resource: "content",
      action: "read",
    },
    {
      name: "content:create",
      description: "Create content",
      resource: "content",
      action: "create",
    },
    {
      name: "content:update",
      description: "Update content",
      resource: "content",
      action: "update",
    },
    {
      name: "content:delete",
      description: "Delete content",
      resource: "content",
      action: "delete",
    },
    {
      name: "content:moderate",
      description: "Moderate content",
      resource: "content",
      action: "moderate",
    },
  ];

  console.log("🔐 Creating permissions...");
  for (const permissionData of permissions) {
    const permission = await prisma.permission.upsert({
      where: { name: permissionData.name },
      update: {},
      create: permissionData,
    });
    console.log(`✅ Created/Updated permission: ${permission.name}`);
  }

  // Assign permissions to roles
  console.log("🔗 Assigning permissions to roles...");

  // Admin gets all permissions
  const adminRole = await prisma.role.findUnique({ where: { name: "ADMIN" } });
  if (adminRole) {
    for (const permission of permissions) {
      const perm = await prisma.permission.findUnique({
        where: { name: permission.name },
      });
      if (perm) {
        await prisma.rolePermission.upsert({
          where: {
            roleId_permissionId: {
              roleId: adminRole.id,
              permissionId: perm.id,
            },
          },
          update: {},
          create: {
            roleId: adminRole.id,
            permissionId: perm.id,
          },
        });
      }
    }
    console.log("✅ Assigned all permissions to ADMIN role");
  }

  // User gets basic permissions
  const userRole = await prisma.role.findUnique({ where: { name: "USER" } });
  if (userRole) {
    const userPermissions = [
      "profile:read",
      "profile:update",
      "content:read",
      "content:create",
    ];
    for (const permName of userPermissions) {
      const perm = await prisma.permission.findUnique({
        where: { name: permName },
      });
      if (perm) {
        await prisma.rolePermission.upsert({
          where: {
            roleId_permissionId: {
              roleId: userRole.id,
              permissionId: perm.id,
            },
          },
          update: {},
          create: {
            roleId: userRole.id,
            permissionId: perm.id,
          },
        });
      }
    }
    console.log("✅ Assigned basic permissions to USER role");
  }

  // Moderator gets content moderation permissions
  const moderatorRole = await prisma.role.findUnique({
    where: { name: "MODERATOR" },
  });
  if (moderatorRole) {
    const moderatorPermissions = [
      "profile:read",
      "profile:update",
      "content:read",
      "content:create",
      "content:update",
      "content:moderate",
      "users:read",
    ];
    for (const permName of moderatorPermissions) {
      const perm = await prisma.permission.findUnique({
        where: { name: permName },
      });
      if (perm) {
        await prisma.rolePermission.upsert({
          where: {
            roleId_permissionId: {
              roleId: moderatorRole.id,
              permissionId: perm.id,
            },
          },
          update: {},
          create: {
            roleId: moderatorRole.id,
            permissionId: perm.id,
          },
        });
      }
    }
    console.log("✅ Assigned moderation permissions to MODERATOR role");
  }

  // Manager gets management permissions
  const managerRole = await prisma.role.findUnique({
    where: { name: "MANAGER" },
  });
  if (managerRole) {
    const managerPermissions = [
      "profile:read",
      "profile:update",
      "content:read",
      "content:create",
      "content:update",
      "content:delete",
      "users:read",
      "users:update",
    ];
    for (const permName of managerPermissions) {
      const perm = await prisma.permission.findUnique({
        where: { name: permName },
      });
      if (perm) {
        await prisma.rolePermission.upsert({
          where: {
            roleId_permissionId: {
              roleId: managerRole.id,
              permissionId: perm.id,
            },
          },
          update: {},
          create: {
            roleId: managerRole.id,
            permissionId: perm.id,
          },
        });
      }
    }
    console.log("✅ Assigned management permissions to MANAGER role");
  }

  console.log("🎉 Database seeding completed successfully!");
}

main()
  .catch((e) => {
    console.error("❌ Seeding failed:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

