import { Router } from 'express';
import { userController } from '@/controllers/userController';
import { authenticate, requireOwnership } from '@/middleware/auth';
import { requireAdminOrModerator } from '@/middleware/roleAuth';
import { validate, validationSchemas } from '@/middleware/validation';

const router = Router();

// User profile routes
router.get(
  '/:id',
  authenticate,
  validate(validationSchemas.uuid),
  requireOwnership('id'),
  userController.getUserById
);

router.put(
  '/:id',
  authenticate,
  validate(validationSchemas.uuid),
  requireOwnership('id'),
  userController.updateUser
);

router.put(
  '/:id/profile',
  authenticate,
  validate(validationSchemas.uuid),
  validate(validationSchemas.updateProfile),
  requireOwnership('id'),
  userController.updateUserProfile
);

router.delete(
  '/:id',
  authenticate,
  validate(validationSchemas.uuid),
  requireOwnership('id'),
  userController.deleteUser
);

// User files routes
router.get(
  '/:id/files',
  authenticate,
  validate(validationSchemas.uuid),
  validate(validationSchemas.pagination),
  requireOwnership('id'),
  userController.getUserFiles
);

// User activity routes (admin/moderator only)
router.get(
  '/:id/activity',
  authenticate,
  validate(validationSchemas.uuid),
  requireAdminOrModerator,
  userController.getUserActivity
);

// Search users (admin/moderator only)
router.get(
  '/',
  authenticate,
  requireAdminOrModerator,
  validate(validationSchemas.pagination),
  userController.searchUsers
);

export default router;