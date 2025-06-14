import jwt, { SignOptions } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { ApiResponse, AppError } from '@/types';

// JWT utilities
export const jwtUtils = {
  sign: (payload: object, expiresIn?: string): string => {
    // Use environment variable or fallback to a development secret
    const secret = process.env.JWT_SECRET || 'your_strong_secret_key_for_development';
    
    if (!secret) {
      throw new Error('JWT_SECRET environment variable is not set');
    }
    
    // Log the payload being signed (for debugging)
    logger.debug('JWT Payload for signing:', JSON.stringify(payload));
    
    // Ensure userId is a string to prevent comparison issues
    if (payload && typeof payload === 'object' && 'userId' in payload) {
      const typedPayload = payload as any;
      if (typedPayload.userId && typeof typedPayload.userId !== 'string') {
        logger.debug(`Converting userId from ${typeof typedPayload.userId} to string`);
        typedPayload.userId = String(typedPayload.userId);
      }
    }
    
    // Define the expiration time string
    const expiration = expiresIn || process.env.JWT_EXPIRES_IN || "7d";
    
    // Type assertion to handle the string expiration time
    return jwt.sign(payload, secret, { expiresIn: expiration as any });
  },

  verify: (token: string): any => {
    const secret = process.env.JWT_SECRET || 'your_strong_secret_key_for_development';
    if (!secret) {
      throw new Error('JWT_SECRET environment variable is not set');
    }
    
    try {
      const decoded = jwt.verify(token, secret);
      logger.debug('JWT Decoded:', JSON.stringify(decoded));
      
      // Ensure userId is a string to prevent comparison issues
      if (decoded && typeof decoded === 'object' && 'userId' in decoded) {
        const typedDecoded = decoded as any;
        if (typedDecoded.userId && typeof typedDecoded.userId !== 'string') {
          logger.debug(`Converting decoded userId from ${typeof typedDecoded.userId} to string`);
          typedDecoded.userId = String(typedDecoded.userId);
        }
      }
      
      return decoded;
    } catch (error) {
      logger.error('JWT Verification Error:', error);
      throw error;
    }
  },

  decode: (token: string): any => {
    return jwt.decode(token);
  }
};

// Password utilities
export const passwordUtils = {
  hash: async (password: string): Promise<string> => {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  },
  compare: async (password: string, hash: string): Promise<boolean> => {
    try {
      if (!password || !hash) {
        logger.error(`Password comparison error: ${!password ? 'Password is empty' : 'Hash is empty'}`);
        return false;
      }
      logger.debug(`Comparing password (length: ${password.length}) with hash (length: ${hash.length})`);
      return await bcrypt.compare(password, hash);
    } catch (error) {
      logger.error('Password comparison error:', error);
      return false;
    }
  }
};

// Response utilities
export const responseUtils = {
  success: <T>(data?: T, message = 'Success'): ApiResponse<T> => ({
    success: true,
    message,
    data
  }),

  error: (message: string, error?: string): ApiResponse => ({
    success: false,
    message,
    error
  }),

  paginated: <T>(
    data: T[], 
    meta: any, 
    message = 'Data retrieved successfully'
  ): ApiResponse<T[]> => ({
    success: true,
    message,
    data,
    pagination: meta
  })
};

// Validation utilities
export const validationUtils = {
  isEmail: (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },

  isStrongPassword: (password: string): boolean => {
    // At least 8 characters, 1 uppercase, 1 lowercase, 1 number
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
  },

  isValidUsername: (username: string): boolean => {
    // 3-20 characters, alphanumeric and underscore only
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(username);
  },

  sanitizeString: (str: string): string => {
    return str.trim().replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  }
};

// File utilities
export const fileUtils = {
  generateFileName: (originalName: string): string => {
    const extension = originalName.split('.').pop();
    const uuid = uuidv4();
    return `${uuid}.${extension}`;
  },

  isAllowedFileType: (mimetype: string): boolean => {
    const allowedTypes = process.env.ALLOWED_FILE_TYPES?.split(',') || [
      'image/jpeg',
      'image/png',
      'image/gif',
      'application/pdf',
      'text/plain'
    ];
    return allowedTypes.includes(mimetype);
  },

  formatFileSize: (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  },

  isFileSizeValid: (size: number): boolean => {
    const maxSize = parseInt(process.env.MAX_FILE_SIZE || '10485760'); // 10MB default
    return size <= maxSize;
  }
};

// Date utilities
export const dateUtils = {
  formatDate: (date: Date | string): string => {
    const d = new Date(date);
    return d.toISOString().split('T')[0];
  },

  formatDateTime: (date: Date | string): string => {
    return new Date(date).toISOString();
  },

  isDateValid: (date: string): boolean => {
    return !isNaN(Date.parse(date));
  },

  addDays: (date: Date, days: number): Date => {
    const result = new Date(date);
    result.setDate(result.getDate() + days);
    return result;
  }
};

// Error handling utilities
export const errorUtils = {
  createError: (message: string, statusCode = 500): AppError => {
    return new AppError(message, statusCode);
  },

  handleDatabaseError: (error: any): AppError => {
    if (error.code === '23505') {
      return new AppError('Resource already exists', 409);
    }
    if (error.code === '23503') {
      return new AppError('Referenced resource not found', 404);
    }
    if (error.code === '42P01') {
      return new AppError('Database table not found', 500);
    }
    return new AppError(error.message || 'Database error', 500);
  }
};

// Pagination utilities
export const paginationUtils = {
  validatePaginationParams: (page?: string, limit?: string) => {
    const pageNum = page ? parseInt(page, 10) : 1;
    const limitNum = limit ? parseInt(limit, 10) : 10;

    if (pageNum < 1) {
      throw new AppError('Page must be greater than 0', 400);
    }

    if (limitNum < 1 || limitNum > 100) {
      throw new AppError('Limit must be between 1 and 100', 400);
    }

    return { page: pageNum, limit: limitNum };
  }
};

// Logging utilities
export const logger = {
  info: (message: string, meta?: any) => {
    console.log(`[INFO] ${new Date().toISOString()}: ${message}`, meta || '');
  },

  error: (message: string, error?: any) => {
    console.error(`[ERROR] ${new Date().toISOString()}: ${message}`, error || '');
  },

  warn: (message: string, meta?: any) => {
    console.warn(`[WARN] ${new Date().toISOString()}: ${message}`, meta || '');
  },

  debug: (message: string, meta?: any) => {
    if (process.env.NODE_ENV !== 'production') {
      console.debug(`[DEBUG] ${new Date().toISOString()}: ${message}`, meta || '');
    }
  },
    userInfo: (user: any) => {
    if (!user) return 'No user';
    return `User[id:${user.id}, email:${user.email}, role:${user.role}]`;
  }
};