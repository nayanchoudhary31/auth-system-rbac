import { Router } from "express";
import {
  getUserProfileHandlder,
  updateUserHandler,
  updateUserProfileHandler,
  changePasswordHandler,
  getUserSessionsHandler,
  revokeSessionHandler,
  revokeAllSessionsHandler,
  deactivateAccountHandler,
  deleteAccountHandler,
} from "../controllers/user-controller.js";
import jwtMiddleware from "../middlewares/jwt.js";

const router = Router();

// All user routes require authentication
router.use(jwtMiddleware.authenticate);

// Profile management
router.get("/profile", getUserProfileHandlder);
router.patch("/update", updateUserHandler);
router.patch("/profile", updateUserProfileHandler);

// Password management
router.post("/change-password", changePasswordHandler);

// Session management
router.get("/sessions", getUserSessionsHandler);
router.delete("/sessions/:sessionId", revokeSessionHandler);
router.delete("/sessions", revokeAllSessionsHandler);

// Account management
router.post("/deactivate", deactivateAccountHandler);
router.delete("/account", deleteAccountHandler);

export default router;
