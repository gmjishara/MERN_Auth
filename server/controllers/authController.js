import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import { generateVerificationCode } from "../utils/generateVerificationCode.js";
import { getAccessToken } from "../utils/getAccessToken.js";

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
      verifyOtpExpireAt: Date.now() + 24 * 60 * 60 * 1000,
    });
    await user.save();

    // don't send token in the register stage

    // const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    //   expiresIn: "7d",
    // });

    // res.cookie("token", token, {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === "production",
    //   sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    //   maxAge: 7 * 24 * 60 * 60 * 100,
    // });

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
    generateTokenAndSetCookie(res, user);

    res.json({ success: true, accessToken });
  } catch (error) {}
};

const refresh = async (req, res) => {
  const cookies = req.cookies;
  const refreshToken = cookies?.jwt;

  if (!refreshToken)
    return res.status(401).json({ success: false, message: "Unauthorized" });

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

      const accessToken = getAccessToken(user);

      res.json({ success: true, accessToken });
    }
  );
};
