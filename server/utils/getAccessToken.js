export const getAccessToken = (user) => {
  const token = jwt.sign(
    {
      UserInfo: {
        firstName: user.firstName,
        lastName: user.lastName,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: "1h",
    }
  );

  return token;
};
