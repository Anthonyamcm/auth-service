import {
  createLogger,
  format,
  transports,
  Logger as WinstonLogger,
} from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import * as dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Destructure format components for easier access
const { combine, timestamp, errors, json, printf, colorize } = format;

// Determine the current environment (development, production, etc.)
const environment = process.env.NODE_ENV || 'development';

// Define custom format for development
const devFormat = combine(
  colorize(),
  timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  errors({ stack: true }), // Capture stack traces for errors
  printf(({ timestamp, level, message, stack, ...metadata }) => {
    return stack
      ? `${timestamp} [${level}]: ${message} - ${stack}`
      : `${timestamp} [${level}]: ${message} ${
          Object.keys(metadata).length ? JSON.stringify(metadata, null, 2) : ''
        }`;
  })
);

// Define custom format for production
const prodFormat = combine(timestamp(), errors({ stack: true }), json());

// Initialize Winston logger
const Logger: WinstonLogger = createLogger({
  level:
    process.env.LOG_LEVEL || (environment === 'production' ? 'info' : 'debug'),
  format: environment === 'production' ? prodFormat : devFormat,
  defaultMeta: { service: 'auth-service' },
  transports: [
    // Console transport
    new transports.Console({
      handleExceptions: true,
      format: environment === 'production' ? prodFormat : devFormat,
    }),

    // Daily Rotate File transport for error logs
    new DailyRotateFile({
      level: 'error',
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      handleExceptions: true,
      format: combine(timestamp(), errors({ stack: true }), json()),
    }),

    // Daily Rotate File transport for combined logs
    new DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      handleExceptions: true,
      format: combine(timestamp(), errors({ stack: true }), json()),
    }),
  ],
  exceptionHandlers: [new transports.File({ filename: 'logs/exceptions.log' })],
  exitOnError: false, // Prevent exiting on handled exceptions
});

// Export the singleton logger instance
export default Logger;
