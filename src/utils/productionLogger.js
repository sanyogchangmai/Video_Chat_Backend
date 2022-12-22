import {createLogger, format, transports} from "winston";
const {combine, timestamp, printf} = format;

const myFormat = printf(({level, message, timestamp}) => {
    return `${level} ${timestamp} ${message}`;
});

const productionLogger = () => {
    return createLogger({
        level: "http",
        format: combine(timestamp(), myFormat),
        defaultMeta: {service: "user-service"},
        transports: [
            new transports.Console(),
            new transports.File({
                filename: "logs/errors.log",
                level: "error",
                format: format.json(),
            }),
            new transports.File({
                filename: "logs/all.log",
                format: format.json(),
            }),
        ],
    });
};

export default productionLogger;
