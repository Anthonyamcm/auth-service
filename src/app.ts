import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import xssClean from 'xss-clean';
import morgan from 'morgan';
import dotenv from 'dotenv';

import authRouter from './controllers/auth.controller';
import { errorHandler } from './middlewares/error.middleware';
import { setupSwagger } from './utils/swagger';

dotenv.config();

const app = express();

// Security Middlewares
app.use(helmet());
app.use(cors());
app.use(xssClean());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
});
app.use(limiter);

// Logging Middleware
app.use(morgan('combined'));

// Body Parser Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/auth', authRouter);

// Swagger Documentation
setupSwagger(app);

// Error Handling Middleware
app.use(errorHandler);

export default app;
