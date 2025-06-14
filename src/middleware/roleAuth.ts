import { Response, NextFunction } from 'express';
import { AuthenticatedRequest, UserRole } from '@/types';
import { responseUtils, logger } from '@/utils/helpers';

// Role-based access control middleware
export const requireRole = (allowedRoles: UserRole | UserRole[]) => {
  return (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): void => {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('Authentication required')
        );
      }

      const userRole = req.user.role as UserRole;
      const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

      if (!roles.includes(userRole)) {
        logger.warn(`Access denied for user ${req.user.id} with role ${userRole}. Required roles: ${roles.join(', ')}`);
        return res.status(403).json(
          responseUtils.error('Insufficient permissions')
        );
      }

      next();

    } catch (error) {
      logger.error('Role authorization error:', error);
      res.status(500).json(
        responseUtils.error('Authorization check failed')
      );
    }
  };
};

// Admin only access
export const requireAdmin = requireRole(UserRole.ADMIN);

// Admin or Moderator access
export const requireAdminOrModerator = requireRole([UserRole.ADMIN, UserRole.MODERATOR]);

// Check if user is admin
export const isAdmin = (req: AuthenticatedRequest): boolean => {
  return req.user?.role === UserRole.ADMIN;
};

// Check if user is moderator or admin
export const isModerator = (req: AuthenticatedRequest): boolean => {
  return req.user?.role === UserRole.MODERATOR || req.user?.role === UserRole.ADMIN;
};

// Permission-based middleware (more granular than roles)
export const requirePermission = (permission: string) => {
  return (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): void => {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('Authentication required')
        );
      }

      const userRole = req.user.role as UserRole;

      // Define permissions for each role
      const rolePermissions: Record<UserRole, string[]> = {
        [UserRole.ADMIN]: [
          'user:read',
          'user:write',
          'user:delete',
          'file:read',
          'file:write',
          'file:delete',
          'admin:read',
          'admin:write',
          'system:manage'
        ],
        [UserRole.MODERATOR]: [
          'user:read',
          'file:read',
          'file:delete',
          'admin:read'
        ],
        [UserRole.USER]: [
          'file:read',
          'file:write',
          'profile:read',
          'profile:write'
        ]
      };

      const userPermissions = rolePermissions[userRole] || [];

      if (!userPermissions.includes(permission)) {
        logger.warn(`Access denied for user ${req.user.id}. Missing permission: ${permission}`);
        return res.status(403).json(
          responseUtils.error('Insufficient permissions')
        );
      }

      next();

    } catch (error) {
      logger.error('Permission check error:', error);
      res.status(500).json(
        responseUtils.error('Permission check failed')
      );
    }
  };
};

// Resource-based access control
export const requireResourceAccess = (resourceType: 'file' | 'user') => {
  return (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): void => {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('Authentication required')
        );
      }

      const userRole = req.user.role as UserRole;
      const resourceId = req.params.id;

      // Admins have access to all resources
      if (userRole === UserRole.ADMIN) {
        return next();
      }

      // For regular users, check if they're accessing their own resources
      if (resourceType === 'user') {
        const targetUserId = req.params.userId || req.params.id;
        if (req.user.id !== targetUserId) {
          return res.status(403).json(
            responseUtils.error('Access denied: You can only access your own profile')
          );
        }
      }

      // For files, the ownership check is handled in the requireOwnership middleware
      // This is just for additional role-based checks
      if (resourceType === 'file') {
        // Moderators can access files for moderation purposes
        if (userRole === UserRole.MODERATOR) {
          return next();
        }
      }

      next();

    } catch (error) {
      logger.error('Resource access check error:', error);
      res.status(500).json(
        responseUtils.error('Resource access check failed')
      );
    }
  };
};

// Check if user can perform action on resource
export const canPerformAction = (
  req: AuthenticatedRequest,
  action: 'read' | 'write' | 'delete',
  resourceType: 'user' | 'file' | 'admin'
): boolean => {
  if (!req.user) return false;

  const userRole = req.user.role as UserRole;

  // Admin can do everything
  if (userRole === UserRole.ADMIN) return true;

  // Define action permissions by role
  const actionPermissions: Record<UserRole, Record<string, string[]>> = {
    [UserRole.ADMIN]: {
      user: ['read', 'write', 'delete'],
      file: ['read', 'write', 'delete'],
      admin: ['read', 'write', 'delete']
    },
    [UserRole.MODERATOR]: {
      user: ['read'],
      file: ['read', 'delete'],
      admin: ['read']
    },
    [UserRole.USER]: {
      user: ['read', 'write'], // Only own profile
      file: ['read', 'write', 'delete'], // Only own files
      admin: []
    }
  };

  const permissions = actionPermissions[userRole]?.[resourceType] || [];
  return permissions.includes(action);
};