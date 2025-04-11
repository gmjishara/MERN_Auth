import express from "express";
import {
  emailVerification,
  login,
  refresh,
  register,
  resendVerificationEmail,
} from "../controllers/authController.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/email:re-send", resendVerificationEmail);
router.post("/email:verify", emailVerification);

export default router;
