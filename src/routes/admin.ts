import { Router } from 'express';
import { adminController } from '@/controllers/adminController';
import { authenticate } from '@/middleware/auth';
import { requireAdmin } from '@/middleware/roleAuth';
import { validate, validationSchemas } from '@/middleware/validation';

const router = Router();

// All admin routes require authentication and admin role
router.use(authenticate);
router.use(requireAdmin);

// Dashboard and statistics
router.get(
  '/dashboard',
  adminController.getDashboardStats
);

router.get(
  '/storage-stats',
  adminController.getStorageStats
);

// User management
router.get(
  '/users',
  validate(validationSchemas.pagination),
  adminController.getAllUsers
);

router.post(
  '/users',
  validate(validationSchemas.register),
  adminController.createUser
);

router.put(
  '/users/:userId/role',
  validate(validationSchemas.updateUserRole),
  adminController.updateUserRole
);

router.put(
  '/users/:userId/deactivate',
  validate(validationSchemas.uuid),
  adminController.deactivateUser
);

router.put(
  '/users/:userId/activate',
  validate(validationSchemas.uuid),
  adminController.activateUser
);

router.delete(
  '/users/:userId',
  validate(validationSchemas.uuid),
  adminController.deleteUser
);

router.post(
  '/users/:userId/reset-password',
  validate(validationSchemas.uuid),
  validate({
    body: validationSchemas.changePassword.body.extract(['new_password'])
  }),
  adminController.resetUserPassword
);

// Bulk operations
router.post(
  '/users/bulk-actions',
  validate({
    body: {
      action: validationSchemas.updateUserRole.body.extract(['role']).rename('action', 'role'),
      user_ids: require('joi').array().items(require('joi').string().uuid()).min(1).required()
    }
  }),
  adminController.bulkUserActions
);

// System logs and audit trail
router.get(
  '/logs',
  validate(validationSchemas.pagination),
  adminController.getSystemLogs
);

export default router;