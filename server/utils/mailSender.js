import nodemailer from "nodemailer";

export const mailSender = async (options) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // true for port 465, false for other ports
    auth: {
      user: process.env.USER,
      pass: process.env.APP_PASSWORD,
    },
  });

  try {
    await transporter.sendMail(options);
    console.log("Email has been sent");
  } catch (error) {
    console.log(error);
  }
};
