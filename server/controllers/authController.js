import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import { generateVerificationCode } from "../utils/generateVerificationCode.js";
import { getAccessToken } from "../utils/getAccessToken.js";
import { mailSender } from "../utils/mailSender.js";
import {
  emailVerificationOptions,
  resetPasswordOptions,
} from "../utils/mailOptions.js";

//user register
export const register = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  const canSave = Boolean(firstName && lastName && email && password);
  if (!canSave) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required!" });
  }

  try {
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verifyOtp = generateVerificationCode();

    const user = new userModel({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      verifyOtp,
      verifyOtpExpireAt: Date.now() + 5 * 60 * 1000,
    });
    await user.save();

    //send otp to user email
    await mailSender(emailVerificationOptions(user));

    res.status(201).json({
      success: true,
      message: "User created successfully",
      user: {
        ...user._doc,
        password: undefined,
      },
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//user login
export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(401).json({
      success: false,
      message: "Email and password are required!",
    });
  }

  try {
    //check user is exist
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    //check password is correct
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid email or password" });
    }

    //create access token
    const accessToken = getAccessToken(user);

    //set refresh token in the cookies
    const refreshToken = generateTokenAndSetCookie(res, user);

    //save token in db
    user.token = refreshToken;
    await user.save();

    res.status(200).json({ success: true, accessToken });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//refresh token method
export const refresh = async (req, res) => {
  const cookies = req.cookies;
  const refreshToken = cookies?.jwt;

  if (!refreshToken)
    return res.status(401).json({ success: false, message: "Unauthorized" });

  try {
    //verify refresh token by jwt
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      async (error, decoded) => {
        if (error)
          return res
            .status(403)
            .json({ success: false, message: "Unauthorized" });

        const user = await userModel.findById(decoded.userId);

        if (!user)
          return res
            .status(401)
            .json({ success: false, message: "Unauthorized" });

        if (!user.token || user.token !== refreshToken) {
          return res
            .status(401)
            .json({ success: false, message: "Unauthorized" });
        }

        //create new access token
        const accessToken = getAccessToken(user);

        //create new refresh token
        const newRefreshToken = generateTokenAndSetCookie(res, user);

        user.token = newRefreshToken;
        await user.save();

        res.json({ success: true, accessToken });
      }
    );
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//re send verification code
export const resendVerificationEmail = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(404)
      .json({ success: false, message: "Email is required!" });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found!" });
    }

    const verifyOtp = generateVerificationCode();

    user.verifyOtp = verifyOtp;
    user.verifyOtpExpireAt = Date.now() + 5 * 60 * 1000;
    await user.save();

    await mailSender(emailVerificationOptions(user));

    let expiresOn = (user.verifyOtpExpireAt - Date.now()) / (60 * 1000);
    expiresOn = expiresOn.toFixed();

    res.json({
      success: true,
      message: "Email has been sent",
      expiresOn: `${expiresOn} min`,
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//verify email
export const emailVerification = async (req, res) => {
  const { email, verifyOtp } = req.body;

  if (!email || !verifyOtp) {
    return res
      .status(400)
      .json({ success: false, message: "One or more validation error" });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found!" });
    }

    if (user.verifyOtp !== verifyOtp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    if (user.verifyOtpExpireAt < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "OTP is expired. Please request a new OTP",
      });
    }

    user.isAccountVerified = true;
    await user.save();

    res.json({
      success: true,
      message: "Email has been verified successfully",
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//sen forgot password OTP
export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(400)
      .json({ success: false, message: "Email is required!" });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found!" });
    }

    const resetOtp = generateVerificationCode();
    user.resetOtp = resetOtp;
    user.resetOtpExpireAt = Date.now() + 5 * 60 * 1000;
    await user.save();

    await mailSender(resetPasswordOptions(user));

    res.json({
      success: true,
      message: `A password reset OTP has been sent to your registered email ${email}. Please check your inbox.`,
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//reset the password
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.status(400).json({
      success: false,
      message: "Email, OTP and new password are required!",
    });
  }

  try {
    const user = await userModel.findOne({ email });

    if (user.resetOtp !== otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    if (user.resetOtpExpireAt < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "OTP is expired. Please request a new OTP",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;

    await user.save();

    res.json({
      success: true,
      message: "Password has been reset successfully",
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};
