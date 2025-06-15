import { Response } from 'express';
import { AuthenticatedRequest, PaginationQuery } from '@/types';
import { db } from '@/config/database';
import { 
  responseUtils, 
  paginationUtils, 
  validationUtils,
  logger 
} from '@/utils/helpers';

export class UserController {  // Get user profile by ID
  async getUserById(req: AuthenticatedRequest, res: Response): Promise<Response | void>  {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.id;
      const user = await db.getUserById(userId);

      if (!user) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Remove sensitive data
      const { password_hash, ...userResponse } = user;

      res.json(
        responseUtils.success(userResponse, 'User retrieved successfully')
      );

    } catch (error) {
      logger.error('Get user error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve user')
      );
    }
  }

  // Update user profile
  async updateUser(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.id;
      const { username, email } = req.body;

      // Check if user exists
      const existingUser = await db.getUserById(userId);
      if (!existingUser) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Prepare update data
      const updateData: any = {};

      if (username && username !== existingUser.username) {
        // Check if username is already taken
        const userWithUsername = await db.getUserByUsername(username);
        if (userWithUsername && userWithUsername.id !== userId) {
          return res.status(409).json(
            responseUtils.error('Username is already taken')
          );
        }
        updateData.username = validationUtils.sanitizeString(username);
      }

      if (email && email !== existingUser.email) {
        // Check if email is already taken
        const userWithEmail = await db.getUserByEmail(email);
        if (userWithEmail && userWithEmail.id !== userId) {
          return res.status(409).json(
            responseUtils.error('Email is already taken')
          );
        }
        updateData.email = validationUtils.sanitizeString(email.toLowerCase());
      }

      // Update user if there are changes
      if (Object.keys(updateData).length === 0) {
        return res.status(400).json(
          responseUtils.error('No changes provided')
        );
      }

      const updatedUser = await db.updateUser(userId, updateData);
      const { password_hash, ...userResponse } = updatedUser;

      logger.info(`User updated: ${updatedUser.email} by user: ${req.user.email}`);

      res.json(
        responseUtils.success(userResponse, 'User updated successfully')
      );

    } catch (error) {
      logger.error('Update user error:', error);
      res.status(500).json(
        responseUtils.error('Failed to update user')
      );
    }
  }

  // Update user profile (extended)
  async updateUserProfile(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.id;
      const { first_name, last_name, bio, phone, avatar_url } = req.body;

      // Check if user exists
      const existingUser = await db.getUserById(userId);
      if (!existingUser) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Update user profile
      const updatedProfile = await db.updateUserProfile(userId, {
        first_name: first_name ? validationUtils.sanitizeString(first_name) : undefined,
        last_name: last_name ? validationUtils.sanitizeString(last_name) : undefined,
        bio: bio ? validationUtils.sanitizeString(bio) : undefined,
        phone: phone ? validationUtils.sanitizeString(phone) : undefined,
        avatar_url: avatar_url ? validationUtils.sanitizeString(avatar_url) : undefined
      });

      logger.info(`User profile updated: ${existingUser.email} by user: ${req.user.email}`);

      res.json(
        responseUtils.success(updatedProfile, 'User profile updated successfully')
      );

    } catch (error) {
      logger.error('Update user profile error:', error);
      res.status(500).json(
        responseUtils.error('Failed to update user profile')
      );
    }
  }

  // Delete user (soft delete - deactivate)
  async deleteUser(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.id;

      // Check if user exists
      const existingUser = await db.getUserById(userId);
      if (!existingUser) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Prevent self-deletion for admins
      if (req.user.id === userId && req.user.role === 'admin') {
        return res.status(400).json(
          responseUtils.error('Admin users cannot delete their own account')
        );
      }

      // Soft delete by updating status
      await db.updateUser(userId, { 
        is_active: false,
        deactivated_at: new Date().toISOString(),
        deactivated_by: req.user.id
      });

      logger.info(`User deactivated: ${existingUser.email} by user: ${req.user.email}`);

      res.json(
        responseUtils.success(null, 'User account deactivated successfully')
      );

    } catch (error) {
      logger.error('Delete user error:', error);
      res.status(500).json(
        responseUtils.error('Failed to delete user')
      );
    }
  }

  // Get user's files
  async getUserFiles(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.id;

      // Check if user exists
      const user = await db.getUserById(userId);
      if (!user) {
        return res.status(404).json(
          responseUtils.error('User not found')
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

      const result = await db.getUserFiles(userId, pagination);

      res.json(
        responseUtils.paginated(result.files, result.meta, 'User files retrieved successfully')
      );

    } catch (error) {
      logger.error('Get user files error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve user files')
      );
    }
  }

  // Search users (admin/moderator only)
  async searchUsers(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const { q: query, role, is_active } = req.query;
      const { page, limit } = paginationUtils.validatePaginationParams(
        req.query.page as string,
        req.query.limit as string
      );

      // For now, this is a simplified search - in production you'd want
      // to implement proper search functionality in the database service
      const pagination: PaginationQuery = {
        page,
        limit,
        sort_by: req.query.sort_by as string,
        sort_order: req.query.sort_order as 'asc' | 'desc'
      };

      const result = await db.getAllUsers(pagination);

      // Filter results based on query parameters (simplified)
      let filteredUsers = result.users;

      if (query) {
        const searchTerm = query.toString().toLowerCase();
        filteredUsers = filteredUsers.filter(user => 
          user.email.toLowerCase().includes(searchTerm) ||
          user.username.toLowerCase().includes(searchTerm) ||
          (user.profile?.first_name && user.profile.first_name.toLowerCase().includes(searchTerm)) ||
          (user.profile?.last_name && user.profile.last_name.toLowerCase().includes(searchTerm))
        );
      }

      if (role) {
        filteredUsers = filteredUsers.filter(user => user.role === role);
      }

      if (is_active !== undefined) {
        const activeFilter = is_active === 'true';
        filteredUsers = filteredUsers.filter(user => user.is_active === activeFilter);
      }

      // Remove password hashes from all users
      const safeUsers = filteredUsers.map(user => {
        const { password_hash, ...safeUser } = user;
        return safeUser;
      });

      res.json(
        responseUtils.paginated(safeUsers, result.meta, 'Users found successfully')
      );

    } catch (error) {
      logger.error('Search users error:', error);
      res.status(500).json(
        responseUtils.error('Failed to search users')
      );
    }
  }

  // Get user activity/statistics
  async getUserActivity(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const userId = req.params.id;

      // Check if user exists
      const user = await db.getUserById(userId);
      if (!user) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Get user's files for statistics
      const { files } = await db.getUserFiles(userId, { page: 1, limit: 1000 });

      const activity = {
        user_id: userId,
        total_files: files.length,
        total_storage_used: files.reduce((sum, file) => sum + file.size, 0),
        recent_uploads: files
          .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
          .slice(0, 10),
        file_types_distribution: files.reduce((acc, file) => {
          acc[file.mime_type] = (acc[file.mime_type] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
        account_age_days: Math.floor(
          (new Date().getTime() - new Date(user.created_at).getTime()) / (1000 * 60 * 60 * 24)
        ),
        last_activity: user.updated_at
      };

      res.json(
        responseUtils.success(activity, 'User activity retrieved successfully')
      );

    } catch (error) {
      logger.error('Get user activity error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve user activity')
      );
    }
  }
}

export const userController = new UserController();