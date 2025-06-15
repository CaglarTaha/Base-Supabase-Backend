import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest, AppError } from '@/types';
import { jwtUtils, responseUtils, logger } from '@/utils/helpers';
import { db } from '@/config/database';

// JWT Authentication middleware
export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<Response | void> => {
  try {
    const authHeader = req.headers.authorization;
    
    logger.debug(`Auth header: ${authHeader ? 'Present' : 'Missing'}`);

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json(
        responseUtils.error('Access token is required')
      );
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    
    logger.debug(`Token: ${token ? token.substring(0, 10) + '...' : 'Missing'}`);

    if (!token) {
      return res.status(401).json(
        responseUtils.error('Access token is required')
      );
    }

    // Verify JWT token
    let decoded;
    try {
      decoded = jwtUtils.verify(token);
      logger.debug(`Token verified, decoded userId: ${decoded?.userId}`);
    } catch (error: any) {
      logger.error(`Token verification error: ${error.name} - ${error.message}`);
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json(
          responseUtils.error('Access token has expired')
        );
      }
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json(
          responseUtils.error('Invalid access token')
        );
      }
      throw error;
    }    // Get user from database
    const user = await db.getUserById(decoded.userId);
    
    logger.debug(`User lookup result: ${user ? 'Found' : 'Not found'} for userId: ${decoded.userId}`);

    if (!user) {
      return res.status(401).json(
        responseUtils.error('User not found')
      );
    }
    
    // Ensure user.id is a string
    if (user.id && typeof user.id !== 'string') {
      logger.debug(`Converting user.id from ${typeof user.id} to string`);
      user.id = String(user.id);
    }

    // Attach user to request object
    req.user = user;
    logger.debug(`User attached to request: ${logger.userInfo(user)}`);
    next();

  } catch (error) {
    logger.error('Authentication error:', error);
    res.status(500).json(
      responseUtils.error('Authentication failed')
    );
  }
};

// Optional authentication middleware (for routes that work with or without auth)
export const optionalAuthenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(); // Continue without user
    }

    const token = authHeader.substring(7);

    if (!token) {
      return next(); // Continue without user
    }

    try {
      const decoded = jwtUtils.verify(token);
      const user = await db.getUserById(decoded.userId);

      if (user) {
        req.user = user;
      }
    } catch (error) {
      // Ignore authentication errors for optional auth
      logger.debug('Optional authentication failed:', error);
    }

    next();

  } catch (error) {
    logger.error('Optional authentication error:', error);
    next(); // Continue without user on error
  }
};

// Middleware to check if user is authenticated (must be used after authenticate)
export const requireAuth = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  if (!req.user) {
    res.status(401).json(
      responseUtils.error('Authentication required')
    );
    return;
  }
  next();
};

// Middleware to check if user owns the resource
export const requireOwnership = (resourceIdParam: string = 'id') => {  
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<Response | void> => {
    try {
      logger.debug(`RequireOwnership middleware called for ${req.method} ${req.originalUrl}`);
      logger.debug(`Checking ownership for param: ${resourceIdParam}`);
      logger.debug(`User attached to request: ${req.user ? 'Yes' : 'No'}`);
      
      if (!req.user) {
        logger.warn('Authentication required: No user attached to request');
        return res.status(401).json(
          responseUtils.error('Authentication required')
        );
      }

      const resourceId = req.params[resourceIdParam];
      logger.debug(`Resource ID from params (${resourceIdParam}): ${resourceId} (${typeof resourceId})`);
      logger.debug(`User ID from token: ${req.user.id} (${typeof req.user.id})`);
      logger.debug(`User role from token: ${req.user.role}`);
      
      if (!resourceId) {
        logger.warn('Resource ID is missing from params');
        return res.status(400).json(
          responseUtils.error('Resource ID is required')
        );
      }
        // For user profile routes, check if user is accessing their own profile
      if (resourceIdParam === 'userId' || resourceIdParam === 'id') {
        logger.debug(`Checking if user ${req.user.id} has access to resource ${resourceId}`);
        logger.debug(`Exact comparison: ${req.user.id === resourceId ? 'MATCH' : 'NO MATCH'}`);
        logger.debug(`Loose comparison: ${req.user.id == resourceId ? 'MATCH' : 'NO MATCH'}`);
        
        // Try both string comparison and more flexible comparison for safety
        // This handles the case where one might be a string and one a UUID object
        const isExactMatch = req.user.id === resourceId;
        const isLooseMatch = String(req.user.id) === String(resourceId);
        
        logger.debug(`isExactMatch: ${isExactMatch}, isLooseMatch: ${isLooseMatch}`);
        
        if (!isExactMatch && !isLooseMatch && req.user.role !== 'admin') {
          logger.warn(`Access denied: User ${req.user.id} (role: ${req.user.role}) cannot access resource ${resourceId}`);
          return res.status(403).json(
            responseUtils.error('Access denied: You can only access your own resources')
          );
        }
        
        logger.debug(`Access granted: User ${req.user.id} (role: ${req.user.role}) can access resource ${resourceId}`);
      }

      // For file routes, check if user owns the file
      if (req.route?.path?.includes('/files/')) {
        const file = await db.getFileById(resourceId);
        
        if (!file) {
          return res.status(404).json(
            responseUtils.error('File not found')
          );
        }

        if (file.user_id !== req.user.id && req.user.role !== 'admin') {
          return res.status(403).json(
            responseUtils.error('Access denied: You can only access your own files')
          );
        }
      }

      next();

    } catch (error) {
      logger.error('Ownership check error:', error);
      res.status(500).json(
        responseUtils.error('Access control check failed')
      );
    }
  };
};

// Rate limiting for login attempts
const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();

export const rateLimitLogin = (
  req: Request,
  res: Response,
  next: NextFunction
): Response | void => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 5;

  const attempts = loginAttempts.get(ip);

  if (attempts) {
    // Reset if window has passed
    if (now - attempts.lastAttempt > windowMs) {
      loginAttempts.delete(ip);
    } else if (attempts.count >= maxAttempts) {
      const timeLeft = Math.ceil((windowMs - (now - attempts.lastAttempt)) / 1000 / 60);
      return res.status(429).json(
        responseUtils.error(`Too many login attempts. Try again in ${timeLeft} minutes.`)
      );
    }
  }

  next();
};

// Record failed login attempt
export const recordFailedLogin = (req: Request): void => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  
  const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: now };
  attempts.count += 1;
  attempts.lastAttempt = now;
  
  loginAttempts.set(ip, attempts);
};

// Clear login attempts on successful login
export const clearLoginAttempts = (req: Request): void => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  loginAttempts.delete(ip);
};