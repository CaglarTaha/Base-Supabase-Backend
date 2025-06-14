import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

// Import configurations and utilities
import { supabaseConfig } from './config/supabase';
import routes from './routes';
import { responseUtils, logger } from './utils/helpers';
import { AppError } from './types';

// Load environment variables
dotenv.config();

class App {
  public app: express.Application;
  private port: number;

  constructor() {
    this.app = express();
    this.port = parseInt(process.env.PORT || '3000', 10);

    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  private initializeMiddlewares(): void {
    // Security middleware
    this.app.use(helmet({
      crossOriginResourcePolicy: { policy: "cross-origin" }
    }));

    // CORS configuration
    const corsOptions = {
      origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
      credentials: true,
      optionsSuccessStatus: 200,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
    };
    this.app.use(cors(corsOptions));

    // Compression
    this.app.use(compression());

    // Rate limiting
    const limiter = rateLimit({
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
      message: {
        error: 'Too many requests from this IP, please try again later.'
      },
      standardHeaders: true,
      legacyHeaders: false
    });
    this.app.use('/api', limiter);

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Request logging in development
    if (process.env.NODE_ENV === 'development') {
      this.app.use((req: Request, res: Response, next: NextFunction) => {
        logger.debug(`${req.method} ${req.path}`, {
          body: req.body,
          query: req.query,
          ip: req.ip
        });
        next();
      });
    }

    // Add request timestamp
    this.app.use((req: Request, res: Response, next: NextFunction) => {
      req.timestamp = new Date().toISOString();
      next();
    });
  }

  private initializeRoutes(): void {
    // Mount API routes
    this.app.use('/api', routes);

    // Root endpoint
    this.app.get('/', (req: Request, res: Response) => {
      res.json(
        responseUtils.success({
          message: 'FERGO-GRAPH Backend API',
          version: '1.0.0',
          status: 'running',
          timestamp: new Date().toISOString(),
          endpoints: {
            api: '/api',
            health: '/api/health',
            docs: '/api/docs'
          }
        })
      );
    });

    // 404 handler for all other routes
    this.app.use('*', (req: Request, res: Response) => {
      res.status(404).json(
        responseUtils.error(`Cannot ${req.method} ${req.originalUrl}`)
      );
    });
  }

  private initializeErrorHandling(): void {
    // Global error handler
    this.app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
      logger.error('Global error handler:', error);

      // Handle Multer errors
      if (error.message.includes('File size limit exceeded')) {
        return res.status(413).json(
          responseUtils.error('File size exceeds the maximum limit')
        );
      }

      if (error.message.includes('File type') && error.message.includes('not allowed')) {
        return res.status(400).json(
          responseUtils.error(error.message)
        );
      }

      // Handle custom AppError
      if (error instanceof AppError) {
        return res.status(error.statusCode).json(
          responseUtils.error(error.message)
        );
      }

      // Handle JWT errors
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json(
          responseUtils.error('Invalid token')
        );
      }

      if (error.name === 'TokenExpiredError') {
        return res.status(401).json(
          responseUtils.error('Token has expired')
        );
      }

      // Handle validation errors
      if (error.name === 'ValidationError') {
        return res.status(400).json(
          responseUtils.error('Validation failed', error.message)
        );
      }

      // Default error response
      const statusCode = process.env.NODE_ENV === 'production' ? 500 : 500;
      const message = process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : error.message;

      return res.status(statusCode).json(
        responseUtils.error(message, process.env.NODE_ENV === 'development' ? error.stack : undefined)
      );
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason: any) => {
      logger.error('Unhandled Promise Rejection:', reason);
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error: Error) => {
      logger.error('Uncaught Exception:', error);
      process.exit(1);
    });

    // Graceful shutdown
    const gracefulShutdown = (signal: string) => {
      logger.info(`Received ${signal}. Starting graceful shutdown...`);

      process.exit(0);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  }

  public async start(): Promise<void> {
    try {
      // Test database connection
      const isDbConnected = await supabaseConfig.testConnection();
      if (!isDbConnected) {
        throw new Error('Failed to connect to database');
      }

      logger.info('Database connection established');

      // Start server
      this.app.listen(this.port, () => {
        logger.info(`🚀 Server running on port ${this.port}`);
        logger.info(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
        logger.info(`🔗 API URL: http://localhost:${this.port}/api`);
        logger.info(`💾 Database: Connected to Supabase`);
      });

    } catch (error) {
      logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }
}

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      timestamp?: string;
    }
  }
}

// Create and start the application
const app = new App();


// Start the server
app.start().catch((error) => {
  console.log('SUPABASE_URL:', process.env.SUPABASE_URL);
  console.log('Environment variables loaded');
  logger.error('Failed to start application:', error);
  process.exit(1);
});

export default app;