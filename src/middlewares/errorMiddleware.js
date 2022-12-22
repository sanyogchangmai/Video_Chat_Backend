// TODO - send response for invalid tokens

import logger from "../logger/logger.js";

const errorHandler = (err, req, res, next) => {
    const statusCode = res.statusCode ? res.statusCode : 500;
    res.status(statusCode);

    res.json({
        message: err.message,
        stack: process.env.NODE_ENV === "production" ? null : err.stack,
    });

    logger.debug("Error thrown by error middleware.");
    logger.error(err.message);
    if (process.env.NODE_ENV !== "production") {
        logger.debug(err.stack);
    }
};

export default errorHandler;
