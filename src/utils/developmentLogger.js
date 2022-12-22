import winston from "winston";
import {createLogger, format, transports} from "winston";
const {combine, colorize, timestamp, printf} = format;

const myFormat = printf(({level, message, timestamp}) => {
    return `${level} ${timestamp} ${message}`;
});

const colors = {
    error: "red",
    warn: "yellow",
    info: "green",
    http: "magenta",
    debug: "cyan",
};

winston.addColors(colors);

const developmentLogger = () => {
    return createLogger({
        level: "debug",
        format: combine(
            colorize({all: true}),
            timestamp({format: "MMM-DD-YYYY HH:mm:ss"}),
            myFormat
        ),
        defaultMeta: {service: "user-service"},
        transports: [new transports.Console()],
    });
};

export default developmentLogger;
