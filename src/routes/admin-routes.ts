import { Router } from "express";
import {
  // User Management
  getAllUserHandler,
  toggleUserStatusHandler,
  getUserSessionsHandler,
  revokeUserSessionsHandler,
  deleteUserHandler,

  // Role Management
  getAllRolesHandler,
  createRoleHandler,
  updateRoleHandler,
  deleteRoleHandler,

  // Permission Management
  getAllPermissionsHandler,
  createPermissionHandler,

  // Role-Permission Management
  getRolePermissionsHandler,
  assignPermissionToRoleHandler,
  removePermissionFromRoleHandler,

  // User Role Management
  getUserRolesHandler,
  updateUserRoleHandler,
  removeUserRoleHandler,
} from "../controllers/admin-controller.js";
import jwtMiddleware from "../middlewares/jwt.js";

const router = Router();

// All admin routes require authentication and admin role
router.use(jwtMiddleware.authenticate);
router.use(jwtMiddleware.authorize(["ADMIN"]));

// ===== USER MANAGEMENT =====
router.get("/users", getAllUserHandler);
router.patch("/users/:id/status", toggleUserStatusHandler);
router.get("/users/:id/sessions", getUserSessionsHandler);
router.delete("/users/:id/sessions", revokeUserSessionsHandler);
router.delete("/users/:id", deleteUserHandler);

// ===== ROLE MANAGEMENT =====
router.get("/roles", getAllRolesHandler);
router.post("/roles", createRoleHandler);
router.put("/roles/:id", updateRoleHandler);
router.delete("/roles/:id", deleteRoleHandler);

// ===== PERMISSION MANAGEMENT =====
router.get("/permissions", getAllPermissionsHandler);
router.post("/permissions", createPermissionHandler);

// ===== ROLE-PERMISSION MANAGEMENT =====
router.get("/roles/:roleId/permissions", getRolePermissionsHandler);
router.post("/roles/:roleId/permissions", assignPermissionToRoleHandler);
router.delete(
  "/roles/:roleId/permissions/:permissionId",
  removePermissionFromRoleHandler
);

// ===== USER ROLE MANAGEMENT =====
router.get("/users/:id/roles", getUserRolesHandler);
router.put("/users/:id/roles", updateUserRoleHandler);
router.delete("/users/:id/roles/:roleId", removeUserRoleHandler);

export default router;
