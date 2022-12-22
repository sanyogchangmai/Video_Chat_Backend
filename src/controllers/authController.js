import User from "../models/userModel.js";
import logger from "../logger/logger.js";
import sendEmail from "../utils/sendEmail.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// * @desc - SIGNUP CONTROLLER
// * @method - POST
// * @route - /auth/signup
const signUpUser = async (req, res) => {
    const {username, email, password} = req.body;

    // ! handle missing data
    if (!username || !email || !password) {
        logger.info("Missing data. All data not provided during signup.");
        res.status(400).json({
            status: "error",
            code: 400,
            message: "Data missing, please provide all fields.",
        });
    }

    // ! check if user already exists
    const user = await User.findOne({username: username});
    if (user) {
        res.status(409).json({
            status: "error",
            code: 409,
            message: "User already exists.",
        });
    } else {
        // ! hash password
        const salt = bcrypt.genSaltSync(10);
        const hashPassword = bcrypt.hashSync(password, salt);

        // ! create new user
        const userCredentials = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashPassword,
        });

        // ! save user data
        try {
            const result = await userCredentials.save();
            logger.info("User account created successfully.");
            res.status(201).json({
                status: "success",
                code: 201,
                message: "User account created successfully.",
                data: {
                    id: result._id,
                    username: result.username,
                    email: result.email,
                },
            });
        } catch (err) {
            logger.error("Error occured during signup.");
            logger.error(err);
            res.status(500).json({
                status: "error",
                code: 500,
                message: "Failed to create user account. Try again.",
                data: err,
            });
        }
    }
};

// * @desc - LOGIN CONTROLLER
// * @method - POST
// * @route - /auth/login
const loginUser = async (req, res) => {
    const {username, password} = req.body;

    if (!username || !password) {
        logger.info("Missing data. All data not provided during login.");
        res.status(400).json({
            status: "error",
            message: "Data missing, please provide all fields.",
        });
    }

    // ! check if user exists
    const user = await User.findOne({username: username});

    if (user) {
        // ! check if password matches
        if (bcrypt.compareSync(password, user.password) == true) {
            logger.info("User password match.");
            const token = generateToken(user._id);
            res.status(200).json({
                status: "success",
                code: 200,
                message: "User authenticated successfully.",
                data: {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    access_token: token,
                },
            });
        } else {
            logger.info("Password do not match.");
            res.status(401).json({
                status: "error",
                code: 401,
                message: "Wrong password.",
            });
        }
    } else {
        logger.info("No user found with this username.");
        res.status(404).json({
            status: "error",
            message: "No user found with this username.",
        });
    }
};

// * Logout user
const logOutUser = (req, res) => {
    res.clearCookie("access_token").status(200).json({
        status: "success",
        code: 200,
        message: "Logged out successfully.",
    });
};

// * @desc - USER DATA CONTROLLER
// * @method - GET
// * @route - /auth/user/data
const getUser = async (req, res) => {
    const userId = req.body.userId;

    try {
        const user = await User.findOne({_id: userId});
        console.log(user);
        if (user) {
            logger.info("User data fetched successfully");
            res.status(200).json({
                status: "success",
                code: 200,
                message: "User data fetched successfully.",
                data: {
                    username: user.username,
                    email: user.email,
                },
            });
        } else {
            logger.info("No user found with this id.");
            res.status(404).json({
                status: "error",
                code: 404,
                message: "No user found with this id.",
            });
        }
    } catch (err) {
        logger.error("Failed to fetch user data.");
        logger.error(err);
        res.status(500).json({
            status: "error",
            code: 500,
            message: "Failed to fetch user data.",
        });
    }
};

// * @desc - FORGOT PASSWORD CONTROLLER
// * @method - POST
// * @route - /auth/forgot/password
const forgotPassword = async (req, res) => {
    const username = req.body.username;

    // ! handle bad request
    if (!username) {
        logger.debug("Username not provided.");
        res.status(400).json({
            status: "error",
            code: 400,
            message: "Username is required.",
        });
    }

    // ! get email from username
    const user = await User.findOne({username: username});
    if (user) {
        const userEmail = user.email;

        // ! generate resetToken
        const resetToken = crypto.randomBytes(20).toString("hex");

        // ! Hash and set resetPassword token
        const hashedToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        // ! save user resetPasswordToken and resetPasswordExpiration
        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpiration = Date.now() + 30 * 60 * 1000;
        try {
            await user.save();
        } catch (err) {
            logger.debug(
                "Failed to save resetPasswordToken and resetPasswordExpiration"
            );
            res.status(500).json({
                status: "error",
                code: 500,
                message: "Internal server error",
            });
        }

        // ! reset url
        const resetUrl = `${req.protocol}://${req.get(
            "host"
        )}/api/v1/auth/reset/password/${resetToken}`;

        // ! create message to be sent
        const message = `Your password reset link is as follows:\n\n${resetUrl} \n\n If you have not requested this, then please ignore it.`;

        // ! send email
        try {
            await sendEmail({
                email: userEmail,
                subject: "Password recovery mail",
                message,
            });
            res.status(200).json({
                status: "success",
                code: 200,
                message: `Recovery instructions sent to ${userEmail}`,
            });
        } catch (err) {
            logger.debug("Failed to send password recovery email.");
            logger.error(err);
            res.status(500).json({
                status: "success",
                code: 500,
                message: "Internal server error",
            });
        }
    } else {
        logger.info("No user found with this username.");
        res.status(404).json({
            status: "error",
            message: "No user found with this username.",
        });
    }
};

// * @desc - POST REST PASSWORD
// * @method - PUT
// * @route - auth/reset/password/:token
const resetPassword = async (req, res) => {
    const token = req.params.token;

    const resetPasswordToken = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

    // ! find the user to upadte its password
    const user = await User.findOne({
        resetPasswordToken: resetPasswordToken,
        resetPasswordExpiration: {$gt: Date.now()},
    });

    console.log(user);

    // ! if user found update password
    if (user) {
        try {
            // ! hash password
            const salt = bcrypt.genSaltSync(10);
            const hashPassword = bcrypt.hashSync(req.body.password, salt);

            const userBody = {
                password: hashPassword,
                resetPasswordToken: undefined,
                resetPasswordExpire: undefined,
            };
            await User.findByIdAndUpdate(user._id, userBody, {new: true});
            logger.debug("Password updated successfully.");
            res.status(200).json({
                status: "success",
                code: 200,
                message:
                    "Password updated successfully. Login with new password.",
            });
        } catch (err) {
            logger.debug("Failed to update password due to exception.");
            logger.error(err);
            res.status(500).json({
                status: "error",
                code: 500,
                message: "Internal server error.",
            });
        }
    } else {
        res.status(400).json({
            status: "error",
            code: 400,
            message: "Password reset token is invalid.",
        });
    }
};

// ! ---------- FUNCTIONS ----------
// * Generate JWT token
const generateToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: "1d",
    });
};

export {
    signUpUser,
    loginUser,
    logOutUser,
    getUser,
    forgotPassword,
    resetPassword,
};
