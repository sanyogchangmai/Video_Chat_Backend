import express from "express";
import {
    signUpUser,
    loginUser,
    logOutUser,
    forgotPassword,
    getUser,
    resetPassword,
} from "../controllers/authController.js";
const authRouter = express.Router();
import protect from "../middlewares/authMiddleware.js";

authRouter.post("/signup", signUpUser);
authRouter.post("/login", loginUser);
authRouter.post("/logout", logOutUser);
authRouter.get("/user/data", protect, getUser);
authRouter.post("/forgot/password", forgotPassword);
authRouter.put("/reset/password/:token", resetPassword);

export default authRouter;
