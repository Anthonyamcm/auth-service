import { createLogger, format, transports } from 'winston';

export const Logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.json()
  ),
  defaultMeta: { service: 'auth-service' },
  transports: [
    new transports.Console(),
    // Add other transports like File or CloudWatch if needed
  ],
});
