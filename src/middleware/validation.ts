import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { AppError, ValidationSchema } from '@/types';
import { responseUtils } from '@/utils/helpers';

// Validation middleware factory
export const validate = (schema: ValidationSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const errors: string[] = [];

    // Validate body
    if (schema.body) {
      const { error } = schema.body.validate(req.body);
      if (error) {
        errors.push(...error.details.map(detail => detail.message));
      }
    }

    // Validate params
    if (schema.params) {
      const { error } = schema.params.validate(req.params);
      if (error) {
        errors.push(...error.details.map(detail => detail.message));
      }
    }

    // Validate query
    if (schema.query) {
      const { error } = schema.query.validate(req.query);
      if (error) {
        errors.push(...error.details.map(detail => detail.message));
      }
    }

    if (errors.length > 0) {
      return res.status(400).json(
        responseUtils.error('Validation failed', errors.join(', '))
      );
    }

    next();
  };
};

// Common validation schemas
export const validationSchemas = {
  // Auth schemas
  login: {
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
      password: Joi.string().min(1).required().messages({
        'string.min': 'Password cannot be empty',
        'any.required': 'Password is required'
      })
    })
  },

  register: {
    body: Joi.object({
      email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
      }),
      password: Joi.string().min(8).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).required().messages({
        'string.min': 'Password must be at least 8 characters long',
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, and one number',
        'any.required': 'Password is required'
      }),
      username: Joi.string().alphanum().min(3).max(20).required().messages({
        'string.alphanum': 'Username must contain only letters and numbers',
        'string.min': 'Username must be at least 3 characters long',
        'string.max': 'Username cannot exceed 20 characters',
        'any.required': 'Username is required'
      }),
      first_name: Joi.string().min(1).max(50).optional(),
      last_name: Joi.string().min(1).max(50).optional()
    })
  },

  // User profile schemas
  updateProfile: {
    body: Joi.object({
      first_name: Joi.string().min(1).max(50).optional(),
      last_name: Joi.string().min(1).max(50).optional(),
      bio: Joi.string().max(500).optional(),
      phone: Joi.string().pattern(/^\+?[\d\s\-\(\)]+$/).optional().messages({
        'string.pattern.base': 'Please provide a valid phone number'
      })
    })
  },

  // File schemas
  fileUpload: {
    query: Joi.object({
      folder: Joi.string().alphanum().optional()
    })
  },

  // Admin schemas
  updateUserRole: {
    body: Joi.object({
      role: Joi.string().valid('admin', 'user', 'moderator').required().messages({
        'any.only': 'Role must be one of: admin, user, moderator',
        'any.required': 'Role is required'
      })
    }),
    params: Joi.object({
      userId: Joi.string().uuid().required().messages({
        'string.uuid': 'Invalid user ID format',
        'any.required': 'User ID is required'
      })
    })
  },

  // Common schemas
  uuid: {
    params: Joi.object({
      id: Joi.string().uuid().required().messages({
        'string.uuid': 'Invalid ID format',
        'any.required': 'ID is required'
      })
    })
  },

  pagination: {
    query: Joi.object({
      page: Joi.number().integer().min(1).default(1).optional(),
      limit: Joi.number().integer().min(1).max(100).default(10).optional(),
      sort_by: Joi.string().optional(),
      sort_order: Joi.string().valid('asc', 'desc').default('desc').optional()
    })
  },

  // Password change schema
  changePassword: {
    body: Joi.object({
      current_password: Joi.string().required().messages({
        'any.required': 'Current password is required'
      }),
      new_password: Joi.string().min(8).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).required().messages({
        'string.min': 'New password must be at least 8 characters long',
        'string.pattern.base': 'New password must contain at least one uppercase letter, one lowercase letter, and one number',
        'any.required': 'New password is required'
      }),
      confirm_password: Joi.string().valid(Joi.ref('new_password')).required().messages({
        'any.only': 'Password confirmation does not match',
        'any.required': 'Password confirmation is required'
      })
    })
  }
};

// Custom validation middleware for file uploads
export const validateFileUpload = (req: Request, res: Response, next: NextFunction) => {
  if (!req.file && !req.files) {
    return res.status(400).json(
      responseUtils.error('No file uploaded')
    );
  }

  const file = req.file || (Array.isArray(req.files) ? req.files[0] : req.files);
  
  if (!file) {
    return res.status(400).json(
      responseUtils.error('Invalid file upload')
    );
  }

  // Check file size
  const maxSize = parseInt(process.env.MAX_FILE_SIZE || '10485760'); // 10MB
  if (file.size > maxSize) {
    return res.status(400).json(
      responseUtils.error(`File size exceeds maximum limit of ${maxSize / 1024 / 1024}MB`)
    );
  }

  // Check file type
  const allowedTypes = process.env.ALLOWED_FILE_TYPES?.split(',') || [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
    'text/plain'
  ];

  if (!allowedTypes.includes(file.mimetype)) {
    return res.status(400).json(
      responseUtils.error(`File type ${file.mimetype} is not allowed`)
    );
  }

  next();
};