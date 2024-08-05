const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const sendEmail = require("../utils/sendEmail.js")
const { v4 } = require("uuid");
const { userModel } = require("../models/user.js");
const { userTokenModel } = require("../models/userToken.js");

const authRouter = express.Router();

authRouter.post("/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      res.status(400).send({
        isSuccessful: false,
        message: "Email already in use",
      });
      return;
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const token = v4();

    await userModel.create({
      fullName,
      email,
      password: hashedPassword,
      authToken: token,
      authPurpose: "verify-email",
    });

    await sendEmail(
      email,
      "Email Verification",
      `${fullName}Click on this link to verify your email: http://localhost:3000/auth/verify-email/${token}`
    );

    res.status(201).send({
      isSuccessful: true,
      message: "User registered successfully",
    });
  } catch (error) {
    res.status(500).send({
      isSuccessful: false,
      message: "An error occurred during registration",
    });
  }
});


authRouter.get("/verify-email/:token", async (req, res) => {
  try {
    const { token } = req.params;

    const doesUserExist = await userModel.exists({
      authToken: token,
      authPurpose: "verify-email",
    });

    if (!doesUserExist) {
      res.status(404).send({
        isSuccessful: false,
        message: "Invalid token",
      });
      return;
    }

    await userModel.findOneAndUpdate({
      authToken: token,
      authPurpose: "verify-email",
      isEmailVerified: true,
      authToken: "",
      authPurpose: "",
    });

    res.send({
      isSuccessful: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    res.status(500).send({
      isSuccessful: false,
      message: "An error occurred",
    });
  }
});

//login 
authRouter.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await userModel.findOne({ email });

    if (!user) {
      res.status(404).send({
        isSuccessful: false,
        message: "User does not exist!",
      });
      return;
    }

    if (!user.isEmailVerified) {
      res.status(400).send({
        isSuccessful: false,
        message: "Your Email is not verified",
      });
      return;
    }

    const isPasswordValid = bcrypt.compareSync(password, user.password);

    if (!isPasswordValid) {
      res.status(400).send({
        isSuccessful: false,
        message: "Invalid Email or password",
      });
      return;
    }

    const userToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
      },
      process.env.AUTH_KEY
    );

    res.send({
      isSuccessful: true,
      message: "User logged in successfully",
      userDetails: {
        userId: user._id,
        fullName: user.fullName,
        email: user.email,
      },
      accessToken: userToken,
    });
  } catch (err) {
    res.status(500).send({
      isSuccessful: false,
      message: "Internal server error",
    });
  }
});

//forget password routes
authRouter.post("/forget-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await userModel.findOne({ email });

    if (!user) {
      res.status(404).send({
        isSuccessful: false,
        message: "Email not found",
      });
      return;
    }

    const token = v4();

    await userTokenModel({
      userId: user._id,
      token,
    }).save();

    const resetPasswordLink = `http://localhost:3000/auth/reset-password/?token=${token}`;

    await sendEmail(
      email,
      "Reset Password",
      `Please click on this link to reset your password: ${resetPasswordLink}`
    );

    res.send({
      isSuccessful: true,
      message: "Reset password link sent to your email",
    });
  } catch (err) {
    res.status(500).send({
      isSuccessful: false,
      message: "Internal server error",
    });
  }
});

//reset password routes
authRouter.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  try {
    const userToken = await userTokenModel.findOne({ token });

    console.log(userToken);

    if (!userToken) {
      res.status(404).send({
        isSuccessful: false,
        message: "Invalid or expired token",
      });
      return;
    }

    const user = await userModel.findById(userToken.userId);

    if (!user) {
      res.status(404).send({
        isSuccessful: false,
        message: "User not found",
      });
      return;
    }

    user.password = bcrypt.hashSync(newPassword, 10);
    await user.save();

    await userToken.deleteOne({ _id: userToken._id });

    res.send({
      isSuccessful: true,
      message: "Password reset successfully",
    });
  } catch (err) {
    res.status(500).send({
      isSuccessful: false,
      message: "Internal server error",
    });
  }
});

const authenticateUser = async (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    res.status(401).send({
      isSuccessful: false,
      message: "Access Denied. Token not provided",
    });
    return;
  }

  try {
    const decode = jwt.verify(token, process.env.AUTH_KEY);
    req.user = await userModel.findById(decode.userId);
    next();
  } catch (err) {
    res.status(401).send({
      isSuccessful: false,
      message: "Invalid token",
    });
  }
};

authRouter.get("/profile", authenticateUser, async (req, res) => {
  try {
    if (!req.user) {
      res.status(404).send({
        isSuccessful: false,
        message: "User not found",
      });
      return;
    }

    res.send({
      isSuccessful: true,
      userDetails: {
        userId: req.user._id,
        fullName: req.user.fullName,
        email: req.user.email,
      },
    });
  } catch (err) {
    res.status(500).send({
      isSuccessful: false,
      message: "Internal server error",
    });
  }
});

module.exports = authRouter;