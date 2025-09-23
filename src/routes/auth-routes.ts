import express from "express";
import {
  loginUserHandler,
  logoutUserHandler,
  refreshTokenHanlder,
  registerUserHanlder,
} from "../controllers/auth-controller.js";

const router = express.Router();

// Register
router.post("/signup", registerUserHanlder);
// Login
router.post("/login", loginUserHandler);
// Refresh tokens
router.get("/refresh", refreshTokenHanlder);
// Logout
router.post("/logout", logoutUserHandler);

export default router;
