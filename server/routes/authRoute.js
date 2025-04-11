import express from "express";
import {
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

export default router;
