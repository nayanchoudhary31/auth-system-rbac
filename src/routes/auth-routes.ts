import express from "express";
import {
  confirmEmailVerificationHandler,
  forgotPasswordHandler,
  loginUserHandler,
  logoutUserHandler,
  refreshTokenHanlder,
  registerUserHanlder,
  requestEmailVerificationHandler,
  resetPasswordFormHandler,
  resetPasswordHandler,
} from "../controllers/auth-controller.js";

const router = express.Router();

// Register
router.post("/signup", registerUserHanlder);
// Login
router.post("/login", loginUserHandler);
// Refresh tokens
router.post("/refresh", refreshTokenHanlder);
// Logout
router.post("/logout", logoutUserHandler);

router.post("/verify-email/request", requestEmailVerificationHandler);
router.get("/verify-email/confirm", confirmEmailVerificationHandler);

router.post("/password/forgot", forgotPasswordHandler);
router.get("/password/reset", resetPasswordFormHandler);
router.post("/password/reset", resetPasswordHandler);

export default router;
