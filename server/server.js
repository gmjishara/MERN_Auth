import express from "express";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();

import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRoutes from "./routes/authRoute.js";

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    credentials: true,
  })
);

app.get("/", (req, res) => res.json("App working"));
app.use("/api/auth", authRoutes);

app.listen(4000, () => {
  connectDB();
  console.log(`Server started in PORT: 4000`);
});
