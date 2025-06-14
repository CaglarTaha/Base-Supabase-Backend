import { Router } from 'express';
import { authController } from '@/controllers/authController';
import { authenticate, rateLimitLogin } from '@/middleware/auth';
import { validate, validationSchemas } from '@/middleware/validation';

const router = Router();

// Public routes (no authentication required)
router.post(
  '/register',
  validate(validationSchemas.register),
  authController.register
);

router.post(
  '/login',
  rateLimitLogin,
  validate(validationSchemas.login),
  authController.login
);

// Protected routes (authentication required)
router.get(
  '/profile',
  authenticate,
  authController.getProfile
);

router.put(
  '/profile',
  authenticate,
  validate(validationSchemas.updateProfile),
  authController.updateProfile
);

router.post(
  '/change-password',
  authenticate,
  validate(validationSchemas.changePassword),
  authController.changePassword
);

router.post(
  '/refresh-token',
  authenticate,
  authController.refreshToken
);

router.post(
  '/logout',
  authenticate,
  authController.logout
);

router.get(
  '/verify-token',
  authenticate,
  authController.verifyToken
);

export default router;