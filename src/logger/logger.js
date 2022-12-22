import developmentLogger from "../utils/developmentLogger.js";
import productionLogger from "../utils/productionLogger.js";

let logger;

if (process.env.NODE_ENV === "production") {
    logger = productionLogger();
} else {
    logger = developmentLogger();
}

export default logger;
