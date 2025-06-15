import { Response } from 'express';
import { AuthenticatedRequest, PaginationQuery, UserRole } from '@/types';
import { db } from '@/config/database';
import { 
  responseUtils, 
  paginationUtils, 
  passwordUtils,
  validationUtils,
  fileUtils,
  logger 
} from '@/utils/helpers';

export class AdminController {
  // Get dashboard statistics
  async getDashboardStats(req: AuthenticatedRequest, res: Response): Promise<any | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const stats = await db.getAdminStats();

      res.json(
        responseUtils.success(stats, 'Dashboard statistics retrieved successfully')
      );

    } catch (error) {
      logger.error('Get dashboard stats error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve dashboard statistics')
      );
    }
  }

  // Get all users with pagination
  async getAllUsers(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const { page, limit } = paginationUtils.validatePaginationParams(
        req.query.page as string,
        req.query.limit as string
      );

      const pagination: PaginationQuery = {
        page,
        limit,
        sort_by: req.query.sort_by as string,
        sort_order: req.query.sort_order as 'asc' | 'desc'
      };

      const result = await db.getAllUsers(pagination);

      // Remove password hashes from all users
      const safeUsers = result.users.map(user => {
        const { password_hash, ...safeUser } = user;
        return safeUser;
      });

      res.json(
        responseUtils.paginated(safeUsers, result.meta, 'Users retrieved successfully')
      );

    } catch (error) {
      logger.error('Get all users error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve users')
      );
    }
  }

  // Create new user (admin only)
  async createUser(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const { email, username, password, role, first_name, last_name } = req.body;

      // Check if user already exists
      const existingUserByEmail = await db.getUserByEmail(email);
      if (existingUserByEmail) {
        return res.status(409).json(
          responseUtils.error('User with this email already exists')
        );
      }

      const existingUserByUsername = await db.getUserByUsername(username);
      if (existingUserByUsername) {
        return res.status(409).json(
          responseUtils.error('Username is already taken')
        );
      }

      // Hash password
      const passwordHash = await passwordUtils.hash(password);      // Create user
      const user = await db.createUser({
        email: validationUtils.sanitizeString(email.toLowerCase()),
        username: validationUtils.sanitizeString(username),
        password_hash: passwordHash,
        role: role || 'user'
      });

      logger.debug(`Creating user with role: ${role || 'user'}`);

      // Create user profile if additional info provided
      if (first_name || last_name) {
        await db.createUserProfile({
          user_id: user.id,
          first_name: first_name ? validationUtils.sanitizeString(first_name) : undefined,
          last_name: last_name ? validationUtils.sanitizeString(last_name) : undefined,
        });
      }

      // Remove password hash from response
      const { password_hash, ...userResponse } = user;

      logger.info(`User created by admin ${req.user.email}: ${user.email}`);

      res.status(201).json(
        responseUtils.success(userResponse, 'User created successfully')
      );

    } catch (error) {
      logger.error('Create user error:', error);
      res.status(500).json(
        responseUtils.error('Failed to create user')
      );
    }
  }

  // Update user role
  async updateUserRole(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.userId;
      const { role } = req.body;

      // Check if target user exists
      const targetUser = await db.getUserById(userId);
      if (!targetUser) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Prevent changing own role
      if (req.user.id === userId) {
        return res.status(400).json(
          responseUtils.error('You cannot change your own role')
        );
      }

      // Update user role
      const updatedUser = await db.updateUser(userId, { role });
      const { password_hash, ...userResponse } = updatedUser;

      logger.info(`User role updated by admin ${req.user.email}: ${targetUser.email} -> ${role}`);

      res.json(
        responseUtils.success(userResponse, 'User role updated successfully')
      );

    } catch (error) {
      logger.error('Update user role error:', error);
      res.status(500).json(
        responseUtils.error('Failed to update user role')
      );
    }
  }

  // Deactivate user
  async deactivateUser(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.userId;

      // Check if target user exists
      const targetUser = await db.getUserById(userId);
      if (!targetUser) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Prevent deactivating own account
      if (req.user.id === userId) {
        return res.status(400).json(
          responseUtils.error('You cannot deactivate your own account')
        );
      }

      // Deactivate user
      const updatedUser = await db.updateUser(userId, { 
        is_active: false,
        deactivated_at: new Date().toISOString(),
        deactivated_by: req.user.id
      });

      const { password_hash, ...userResponse } = updatedUser;

      logger.info(`User deactivated by admin ${req.user.email}: ${targetUser.email}`);

      res.json(
        responseUtils.success(userResponse, 'User deactivated successfully')
      );

    } catch (error) {
      logger.error('Deactivate user error:', error);
      res.status(500).json(
        responseUtils.error('Failed to deactivate user')
      );
    }
  }

  // Activate user
  async activateUser(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.userId;

      // Check if target user exists
      const targetUser = await db.getUserById(userId);
      if (!targetUser) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }      // Activate user
      const updatedUser = await db.updateUser(userId, { 
        is_active: true,
        activated_at: new Date().toISOString(),
        activated_by: req.user.id,
        deactivated_at: '',
        deactivated_by: ''
      });

      const { password_hash, ...userResponse } = updatedUser;

      logger.info(`User activated by admin ${req.user.email}: ${targetUser.email}`);

      res.json(
        responseUtils.success(userResponse, 'User activated successfully')
      );

    } catch (error) {
      logger.error('Activate user error:', error);
      res.status(500).json(
        responseUtils.error('Failed to activate user')
      );
    }
  }

  // Delete user permanently
  async deleteUser(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.userId;

      // Check if target user exists
      const targetUser = await db.getUserById(userId);
      if (!targetUser) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Prevent deleting own account
      if (req.user.id === userId) {
        return res.status(400).json(
          responseUtils.error('You cannot delete your own account')
        );
      }

      // Prevent deleting other admin accounts (safety measure)
      if (targetUser.role === UserRole.ADMIN && req.user.role === UserRole.ADMIN) {
        return res.status(400).json(
          responseUtils.error('Admin users cannot delete other admin accounts')
        );
      }

      // Delete user permanently
      await db.deleteUser(userId);

      logger.info(`User permanently deleted by admin ${req.user.email}: ${targetUser.email}`);

      res.json(
        responseUtils.success(null, 'User deleted permanently')
      );

    } catch (error) {
      logger.error('Delete user error:', error);
      res.status(500).json(
        responseUtils.error('Failed to delete user')
      );
    }
  }

  // Get system logs/audit trail (placeholder)
  async getSystemLogs(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const { page, limit } = paginationUtils.validatePaginationParams(
        req.query.page as string,
        req.query.limit as string
      );

      // This is a placeholder - in a real application, you'd have a separate
      // logging system and audit trail table
      const logs = [
        {
          id: '1',
          action: 'USER_LOGIN',
          user_id: req.user.id,
          user_email: req.user.email,
          ip_address: req.ip,
          timestamp: new Date().toISOString(),
          details: { success: true }
        },
        {
          id: '2',
          action: 'FILE_UPLOAD',
          user_id: req.user.id,
          user_email: req.user.email,
          ip_address: req.ip,
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          details: { filename: 'example.pdf', size: 1024 }
        }
      ];

      const meta = {
        page,
        limit,
        total: logs.length,
        total_pages: Math.ceil(logs.length / limit),
        has_next: false,
        has_prev: false
      };

      res.json(
        responseUtils.paginated(logs, meta, 'System logs retrieved successfully')
      );

    } catch (error) {
      logger.error('Get system logs error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve system logs')
      );
    }
  }

  // Get storage statistics
  async getStorageStats(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      // Get basic stats from database
      const stats = await db.getAdminStats();

      // Calculate additional storage metrics
      const storageStats = {
        total_storage_used: stats.storage_used,
        total_storage_used_formatted: fileUtils.formatFileSize(stats.storage_used),
        total_files: stats.total_files,
        average_file_size: stats.total_files > 0 ? Math.round(stats.storage_used / stats.total_files) : 0,
        storage_limit: parseInt(process.env.STORAGE_LIMIT || '107374182400'), // 100GB default
        storage_usage_percentage: stats.storage_used / parseInt(process.env.STORAGE_LIMIT || '107374182400') * 100,
        
        // These would be calculated from actual file data in production
        file_type_distribution: {
          'image/jpeg': 45,
          'image/png': 30,
          'application/pdf': 15,
          'text/plain': 5,
          'other': 5
        },
        monthly_upload_trend: [
          { month: 'Jan', uploads: 120, size: 50000000 },
          { month: 'Feb', uploads: 135, size: 55000000 },
          { month: 'Mar', uploads: 150, size: 60000000 },
          { month: 'Apr', uploads: 145, size: 58000000 },
          { month: 'May', uploads: 160, size: 65000000 },
          { month: 'Jun', uploads: 175, size: 70000000 }
        ]
      };

      res.json(
        responseUtils.success(storageStats, 'Storage statistics retrieved successfully')
      );

    } catch (error) {
      logger.error('Get storage stats error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve storage statistics')
      );
    }
  }

  // Reset user password (admin only)
  async resetUserPassword(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.userId;
      const { new_password } = req.body;

      // Check if target user exists
      const targetUser = await db.getUserById(userId);
      if (!targetUser) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Hash new password
      const passwordHash = await passwordUtils.hash(new_password);

      // Update password
      await db.updateUser(userId, { 
        password_hash: passwordHash,
        password_reset_at: new Date().toISOString(),
        password_reset_by: req.user.id
      });

      logger.info(`Password reset by admin ${req.user.email} for user: ${targetUser.email}`);

      res.json(
        responseUtils.success(null, 'User password reset successfully')
      );

    } catch (error) {
      logger.error('Reset user password error:', error);
      res.status(500).json(
        responseUtils.error('Failed to reset user password')
      );
    }
  }

  // Bulk operations
  async bulkUserActions(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const { action, user_ids } = req.body;

      if (!Array.isArray(user_ids) || user_ids.length === 0) {
        return res.status(400).json(
          responseUtils.error('User IDs array is required')
        );
      }      const results: {
        successful: Array<{ user_id: string; email?: string }>;
        failed: Array<{ user_id: string; error: string }>;
      } = {
        successful: [],
        failed: []
      };

      for (const userId of user_ids) {
        try {
          // Prevent actions on own account
          if (userId === req.user.id) {
            results.failed.push({
              user_id: userId,
              error: 'Cannot perform action on own account'
            });
            continue;
          }

          const targetUser = await db.getUserById(userId);
          if (!targetUser) {
            results.failed.push({
              user_id: userId,
              error: 'User not found'
            });
            continue;
          }

          switch (action) {
            case 'deactivate':
              await db.updateUser(userId, { 
                is_active: false,
                deactivated_at: new Date().toISOString(),
                deactivated_by: req.user.id
              });
              break;

            case 'activate':
              await db.updateUser(userId, { 
                is_active: true,
                activated_at: new Date().toISOString(),
                activated_by: req.user.id
              });
              break;

            case 'delete':
              // Prevent deleting admin accounts
              if (targetUser.role === UserRole.ADMIN) {
                results.failed.push({
                  user_id: userId,
                  error: 'Cannot delete admin accounts'
                });
                continue;
              }
              await db.deleteUser(userId);
              break;

            default:
              results.failed.push({
                user_id: userId,
                error: 'Invalid action'
              });
              continue;
          }

          results.successful.push({
            user_id: userId,
            email: targetUser.email
          });

        } catch (error) {
          results.failed.push({
            user_id: userId,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }

      logger.info(`Bulk ${action} operation by admin ${req.user.email}: ${results.successful.length} successful, ${results.failed.length} failed`);

      res.json(
        responseUtils.success(results, `Bulk ${action} operation completed`)
      );

    } catch (error) {
      logger.error('Bulk user actions error:', error);
      res.status(500).json(
        responseUtils.error('Bulk operation failed')
      );
    }
  }
}

export const adminController = new AdminController();