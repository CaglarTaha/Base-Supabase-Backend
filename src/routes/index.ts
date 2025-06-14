import { Router, Request, Response } from 'express';
import authRoutes from './auth';
import userRoutes from './user';
import fileRoutes from './files';
import adminRoutes from './admin';
import { responseUtils } from '@/utils/helpers';

const router = Router();

// Health check endpoint
router.get('/health', (req: Request, res: Response) => {
  res.json(
    responseUtils.success({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development'
    }, 'API is running')
  );
});

// API information endpoint
router.get('/', (req: Request, res: Response) => {
  res.json(
    responseUtils.success({
      name: 'FERGO-GRAPH API',
      version: '1.0.0',
      description: 'Backend API for FERGO-GRAPH application',
      endpoints: {
        auth: '/api/auth',
        users: '/api/users',
        files: '/api/files',
        admin: '/api/admin'
      },
      documentation: '/api/docs' // Future endpoint for API documentation
    }, 'Welcome to FERGO-GRAPH API')
  );
});

// Mount route modules
router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/files', fileRoutes);
router.use('/admin', adminRoutes);

// 404 handler for API routes
router.use('*', (req: Request, res: Response) => {
  res.status(404).json(
    responseUtils.error(`Route ${req.originalUrl} not found`)
  );
});

export default router;