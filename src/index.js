import express from "express";
import cors from "cors";
import * as dotenv from "dotenv";
dotenv.config();

import connectDB from "./config/db.js";
import logger from "./logger/logger.js";
import morganMiddleware from "./middlewares/morganMiddleware.js";
import errorHandler from "./middlewares/errorMiddleware.js";

import authRouter from "./routes/authRoutes.js";

//* Initialize constants
const PORT = process.env.PORT || 8000;

//* Initialize express app
const app = express();

// TODO - connect to db
connectDB();

// * Middleware to grab request body
app.use(express.json());
app.use(
    express.urlencoded({
        extended: false,
    })
);

//* Handle cors
app.use(cors());

// * Morgan middleware
app.use(morganMiddleware);

//* Home route
app.get("/", (req, res) => {
    res.status(200).json({
        status: "success",
        code: 200,
        message: `Server is running at port ${PORT}`,
    });
});

app.use("/api/v1/auth", authRouter);

// * Override express default handler
app.use(errorHandler);

//* Make app to listen at a port
app.listen(PORT, () => {
    logger.info(`Server running at port ${PORT}`);
});
