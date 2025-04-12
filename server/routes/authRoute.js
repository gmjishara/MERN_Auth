import express from "express";
import {
  emailVerification,
  forgotPassword,
  login,
  refresh,
  register,
  resendVerificationEmail,
  resetPassword,
} from "../controllers/authController.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/email:re-send", resendVerificationEmail);
router.post("/email:verify", emailVerification);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

export default router;
