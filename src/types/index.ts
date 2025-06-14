import { Request } from 'express';

// User Types
export interface User {
  id: string;
  email: string;
  username: string;
  role: UserRole;
  password_hash: string; // Eklendi
  is_active?: boolean; // Eklendi
  last_login?: string; // Eklendi
  created_at: string;
  updated_at: string;
  profile?: UserProfile;
}

export interface UserProfile {
  id: string;
  user_id: string;
  first_name?: string;
  last_name?: string;
  avatar_url?: string;
  bio?: string;
  phone?: string;
  created_at: string;
  updated_at: string;
}

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  MODERATOR = 'moderator'
}

// Auth Types
export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
  username: string;
  first_name?: string;
  last_name?: string;
}

// File Types
export interface FileUpload {
  id: string;
  user_id: string;
  filename: string;
  original_name: string;
  mime_type: string;
  size: number;
  url: string;
  created_at: string;
}

// API Response Types
export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: string;
  pagination?: PaginationMeta;
}

export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface PaginationQuery {
  page?: number;
  limit?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

// Request Types
export interface AuthenticatedRequest extends Request {
  user?: User;
}

export interface FileUploadRequest extends AuthenticatedRequest {
  file?: Express.Multer.File;
  files?: Express.Multer.File[];
}

// Database Types
export interface DatabaseConfig {
  url: string;
  apiKey: string;
  serviceRoleKey: string;
}

// Validation Schemas
export interface ValidationSchema {
  body?: any;
  params?: any;
  query?: any;
}

// Error Types
export class AppError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

// Admin Types
export interface AdminStats {
  total_users: number;
  total_files: number;
  active_users_today: number;
  storage_used: number;
}

export interface AdminUser extends User {
  last_login?: string;
  is_active: boolean;
  files_count: number;
}