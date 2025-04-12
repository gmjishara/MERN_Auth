//verify email option
export const emailVerificationOptions = (user) => {
  const { email, firstName, verifyOtp, verifyOtpExpireAt } = user;

  let expiresOn = (verifyOtpExpireAt - Date.now()) / (60 * 1000);
  expiresOn = expiresOn.toFixed();

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
        
                   This code is valid for ${expiresOn} min. Please do not share it with anyone for security reasons.
        
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
                    <p>This code is valid for ${expiresOn} min. Please do not share it with anyone.</p>
                    <p>If you did not request this OTP, please ignore this email or contact our support team immediately at <a href="mailto:${process.env.USER}">${process.env.USER}</a>.</p>
                </div>
                <div>
                    <p>Thank you,<br>Authentik</p>
                </div>
            </div>`, // html body
  };

  return options;
};

//reset password option 
export const resetPasswordOptions = (user) => {
  const { email, firstName, resetOtp, resetOtpExpireAt } = user;

  let expiresOn = (resetOtpExpireAt - Date.now()) / (60 * 1000);
  expiresOn = expiresOn.toFixed();

  const options = {
    from: {
      name: "MERN Authentik",
      address: process.env.USER,
    },
    to: email, // list of receivers
    subject: "Your One-Time Password (OTP) for Reset Password", // Subject line
    text: `Dear ${firstName},
        
                   Your One-Time Password (OTP) for reset password is:
        
                   OTP: ${resetOtp}
        
                   This code is valid for ${expiresOn} min. Please do not share it with anyone for security reasons.
        
                   If you did not request this OTP, please ignore this email or contact our support team immediately at ${process.env.USER}.
        
                   Thank you,
                   Authentik
                   ${process.env.USER}`, // plain text body
    html: `<div>
                <div>
                    <h2>Your One-Time Password (OTP) for Reset Password</h2>
                </div>
                <div>
                    <p>Dear ${firstName},</p>
                    <p>Your One-Time Password (OTP) for reset password is:</p>
                    <h3>${resetOtp}</h3>
                    <p>This code is valid for ${expiresOn} min. Please do not share it with anyone.</p>
                    <p>If you did not request this OTP, please ignore this email or contact our support team immediately at <a href="mailto:${process.env.USER}">${process.env.USER}</a>.</p>
                </div>
                <div>
                    <p>Thank you,<br>Authentik</p>
                </div>
            </div>`, // html body
  };

  return options;
};
