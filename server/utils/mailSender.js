import nodemailer from "nodemailer";

const mailOptions = (user) => {
  const { email, firstName, verifyOtp } = user;

  const options = {
    from: {
      name: "MERN Authentik",
      address: process.env.USER,
    },
    to: email, // list of receivers
    subject: "Your One-Time Password (OTP) for Verification", // Subject line
    text: `Dear ${firstName},
      
                 Your One-Time Password (OTP) for verification is:
      
                 OTP: ${verifyOtp}
      
                 This code is valid for 1 day. Please do not share it with anyone for security reasons.
      
                 If you did not request this OTP, please ignore this email or contact our support team immediately at ${process.env.USER}.
      
                 Thank you,
                 Authentik
                 ${process.env.USER}`, // plain text body
    html: `<div>
              <div>
                  <h2>Your One-Time Password (OTP) for Verification</h2>
              </div>
              <div>
                  <p>Dear ${firstName},</p>
                  <p>Your One-Time Password (OTP) for verification is:</p>
                  <h3>${verifyOtp}</h3>
                  <p>This code is valid for 1 day. Please do not share it with anyone.</p>
                  <p>If you did not request this OTP, please ignore this email or contact our support team immediately at <a href="mailto:${process.env.USER}">${process.env.USER}</a>.</p>
              </div>
              <div>
                  <p>Thank you,<br>Authentik</p>
              </div>
          </div>`, // html body
  };

  return options;
};

export const mailSender = async(user) => {
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

  const options = mailOptions(user);

  try {
    await transporter.sendMail(options);
    console.log("Email has been sent")
  } catch (error) {
    console.log(error);
  }
};
