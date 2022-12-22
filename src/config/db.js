import mongoose from "mongoose";
import logger from "../logger/logger.js";

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.DB_URI);
        logger.info(`Connected to DB ${conn.connection.host}`);
    } catch (err) {
        logger.error(err);
        process.exit(1);
    }
};

export default connectDB;
