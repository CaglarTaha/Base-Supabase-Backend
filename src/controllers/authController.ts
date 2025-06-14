import { Request, Response } from 'express';
import { AuthenticatedRequest, LoginCredentials, RegisterData, AuthTokens } from '@/types';
import { db } from '@/config/database';
import { 
  jwtUtils, 
  passwordUtils, 
  responseUtils, 
  validationUtils, 
  logger 
} from '@/utils/helpers';
import { recordFailedLogin, clearLoginAttempts } from '@/middleware/auth';

export class AuthController {
  // User registration
  async register(req: Request, res: Response): Promise<Response | void> {
    try {
      const { email, password, username, first_name, last_name }: RegisterData = req.body;

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
      const passwordHash = await passwordUtils.hash(password);

      // Create user
      const user = await db.createUser({
        email: validationUtils.sanitizeString(email.toLowerCase()),
        username: validationUtils.sanitizeString(username),
        password_hash: passwordHash,
        role: 'user'
      });

      // Create user profile if additional info provided
      if (first_name || last_name) {
        await db.createUserProfile({
          user_id: user.id,
          first_name: first_name ? validationUtils.sanitizeString(first_name) : undefined,
          last_name: last_name ? validationUtils.sanitizeString(last_name) : undefined
        });
      }

      // Generate JWT token
      const token = jwtUtils.sign({ 
        userId: user.id, 
        email: user.email,
        role: user.role 
      });

      // Remove password hash from response
      const { password_hash, ...userResponse } = user;

      logger.info(`New user registered: ${user.email}`);

      res.status(201).json(
        responseUtils.success({
          user: userResponse,
          token,
          expires_in: process.env.JWT_EXPIRES_IN || '7d'
        }, 'User registered successfully')
      );

    } catch (error) {
      logger.error('Registration error:', error);
      res.status(500).json(
        responseUtils.error('Registration failed')
      );
    }
  }

  // User login
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password }: LoginCredentials = req.body;

      // Find user by email
      const user = await db.getUserByEmail(email.toLowerCase());
      if (!user) {
        recordFailedLogin(req);
        return res.status(401).json(
          responseUtils.error('Invalid email or password')
        );
      }

      // Verify password
      const isPasswordValid = await passwordUtils.compare(password, user.password_hash);
      if (!isPasswordValid) {
        recordFailedLogin(req);
        return res.status(401).json(
          responseUtils.error('Invalid email or password')
        );
      }

      // Clear failed login attempts
      clearLoginAttempts(req);

      // Update last login
      await db.updateUser(user.id, { 
        last_login: new Date().toISOString() 
      });

      // Generate JWT token
      const token = jwtUtils.sign({ 
        userId: user.id, 
        email: user.email,
        role: user.role 
      });

      // Remove sensitive data from response
      const { password_hash, ...userResponse } = user;

      logger.info(`User logged in: ${user.email}`);

      res.json(
        responseUtils.success({
          user: userResponse,
          token,
          expires_in: process.env.JWT_EXPIRES_IN || '7d'
        }, 'Login successful')
      );

    } catch (error) {
      logger.error('Login error:', error);
      res.status(500).json(
        responseUtils.error('Login failed')
      );
    }
  }

  // Get current user profile
  async getProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      // Get fresh user data from database
      const user = await db.getUserById(req.user.id);
      if (!user) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Remove sensitive data
      const { password_hash, ...userResponse } = user;

      res.json(
        responseUtils.success(userResponse, 'Profile retrieved successfully')
      );

    } catch (error) {
      logger.error('Get profile error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve profile')
      );
    }
  }

  // Update user profile
  async updateProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const { first_name, last_name, bio, phone } = req.body;

      // Update user profile
      const updatedProfile = await db.updateUserProfile(req.user.id, {
        first_name: first_name ? validationUtils.sanitizeString(first_name) : undefined,
        last_name: last_name ? validationUtils.sanitizeString(last_name) : undefined,
        bio: bio ? validationUtils.sanitizeString(bio) : undefined,
        phone: phone ? validationUtils.sanitizeString(phone) : undefined
      });

      logger.info(`Profile updated for user: ${req.user.email}`);

      res.json(
        responseUtils.success(updatedProfile, 'Profile updated successfully')
      );

    } catch (error) {
      logger.error('Update profile error:', error);
      res.status(500).json(
        responseUtils.error('Failed to update profile')
      );
    }
  }

  // Change password
  async changePassword(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const { current_password, new_password } = req.body;

      // Get user with password hash
      const user = await db.getUserById(req.user.id);
      if (!user) {
        return res.status(404).json(
          responseUtils.error('User not found')
        );
      }

      // Verify current password
      const isCurrentPasswordValid = await passwordUtils.compare(
        current_password, 
        user.password_hash
      );

      if (!isCurrentPasswordValid) {
        return res.status(400).json(
          responseUtils.error('Current password is incorrect')
        );
      }

      // Hash new password
      const newPasswordHash = await passwordUtils.hash(new_password);

      // Update password
      await db.updateUser(user.id, { 
        password_hash: newPasswordHash 
      });

      logger.info(`Password changed for user: ${user.email}`);

      res.json(
        responseUtils.success(null, 'Password changed successfully')
      );

    } catch (error) {
      logger.error('Change password error:', error);
      res.status(500).json(
        responseUtils.error('Failed to change password')
      );
    }
  }

  // Refresh token
  async refreshToken(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      // Generate new token
      const token = jwtUtils.sign({ 
        userId: req.user.id, 
        email: req.user.email,
        role: req.user.role 
      });

      res.json(
        responseUtils.success({
          token,
          expires_in: process.env.JWT_EXPIRES_IN || '7d'
        }, 'Token refreshed successfully')
      );

    } catch (error) {
      logger.error('Refresh token error:', error);
      res.status(500).json(
        responseUtils.error('Failed to refresh token')
      );
    }
  }

  // Logout (client-side token invalidation)
  async logout(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      // In a JWT-based system, logout is typically handled client-side
      // by removing the token from storage. However, we can log the event.
      
      if (req.user) {
        logger.info(`User logged out: ${req.user.email}`);
      }

      res.json(
        responseUtils.success(null, 'Logged out successfully')
      );

    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json(
        responseUtils.error('Logout failed')
      );
    }
  }

  // Verify token (for client-side token validation)
  async verifyToken(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('Invalid token')
        );
      }

      res.json(
        responseUtils.success({
          valid: true,
          user: {
            id: req.user.id,
            email: req.user.email,
            username: req.user.username,
            role: req.user.role
          }
        }, 'Token is valid')
      );

    } catch (error) {
      logger.error('Verify token error:', error);
      res.status(500).json(
        responseUtils.error('Token verification failed')
      );
    }
  }
}

export const authController = new AuthController();