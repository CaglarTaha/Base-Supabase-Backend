import { supabase, adminSupabase } from './supabase';
import { User, UserProfile, FileUpload, PaginationQuery, PaginationMeta } from '@/types';

export class DatabaseService {
  // User operations
  async createUser(userData: {
    email: string;
    username: string;
    password_hash: string;
    role?: string;
  }): Promise<User> {
    const { data, error } = await adminSupabase
      .from('users')
      .insert([{
        email: userData.email,
        username: userData.username,
        password_hash: userData.password_hash,
        role: userData.role || 'user'
      }])
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async getUserById(id: string): Promise<User | null> {
    const { data, error } = await supabase
      .from('users')
      .select(`
        *,
        profile:user_profiles(*)
      `)
      .eq('id', id)
      .single();

    if (error) return null;
    return data;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const { data, error } = await supabase
      .from('users')
      .select(`
        *,
        profile:user_profiles(*)
      `)
      .eq('email', email)
      .single();

    if (error) return null;
    return data;
  }

  async getUserByUsername(username: string): Promise<User | null> {
    const { data, error } = await supabase
      .from('users')
      .select(`
        *,
        profile:user_profiles(*)
      `)
      .eq('username', username)
      .single();

    if (error) return null;
    return data;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User> {
    const { data, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async deleteUser(id: string): Promise<void> {
    const { error } = await adminSupabase
      .from('users')
      .delete()
      .eq('id', id);

    if (error) throw error;
  }

  // User Profile operations
  async createUserProfile(profileData: {
    user_id: string;
    first_name?: string;
    last_name?: string;
    avatar_url?: string;
    bio?: string;
    phone?: string;
  }): Promise<UserProfile> {
    const { data, error } = await supabase
      .from('user_profiles')
      .insert([profileData])
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async updateUserProfile(userId: string, updates: Partial<UserProfile>): Promise<UserProfile> {
    const { data, error } = await supabase
      .from('user_profiles')
      .update(updates)
      .eq('user_id', userId)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  // File operations
  async createFileRecord(fileData: {
    user_id: string;
    filename: string;
    original_name: string;
    mime_type: string;
    size: number;
    url: string;
  }): Promise<FileUpload> {
    const { data, error } = await supabase
      .from('files')
      .insert([fileData])
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async getFileById(id: string): Promise<FileUpload | null> {
    const { data, error } = await supabase
      .from('files')
      .select('*')
      .eq('id', id)
      .single();

    if (error) return null;
    return data;
  }

  async getUserFiles(userId: string, pagination?: PaginationQuery): Promise<{
    files: FileUpload[];
    meta: PaginationMeta;
  }> {
    const page = pagination?.page || 1;
    const limit = pagination?.limit || 10;
    const offset = (page - 1) * limit;

    // Get total count
    const { count } = await supabase
      .from('files')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', userId);

    // Get files with pagination
    let query = supabase
      .from('files')
      .select('*')
      .eq('user_id', userId)
      .range(offset, offset + limit - 1);

    if (pagination?.sort_by) {
      query = query.order(pagination.sort_by, { 
        ascending: pagination.sort_order === 'asc' 
      });
    } else {
      query = query.order('created_at', { ascending: false });
    }

    const { data, error } = await query;

    if (error) throw error;

    const total = count || 0;
    const totalPages = Math.ceil(total / limit);

    return {
      files: data || [],
      meta: {
        page,
        limit,
        total,
        total_pages: totalPages,
        has_next: page < totalPages,
        has_prev: page > 1
      }
    };
  }

  async deleteFile(id: string): Promise<void> {
    const { error } = await supabase
      .from('files')
      .delete()
      .eq('id', id);

    if (error) throw error;
  }

  // Admin operations
  async getAllUsers(pagination?: PaginationQuery): Promise<{
    users: User[];
    meta: PaginationMeta;
  }> {
    const page = pagination?.page || 1;
    const limit = pagination?.limit || 10;
    const offset = (page - 1) * limit;

    // Get total count
    const { count } = await adminSupabase
      .from('users')
      .select('*', { count: 'exact', head: true });

    // Get users with pagination
    let query = adminSupabase
      .from('users')
      .select(`
        *,
        profile:user_profiles(*)
      `)
      .range(offset, offset + limit - 1);

    if (pagination?.sort_by) {
      query = query.order(pagination.sort_by, { 
        ascending: pagination.sort_order === 'asc' 
      });
    } else {
      query = query.order('created_at', { ascending: false });
    }

    const { data, error } = await query;

    if (error) throw error;

    const total = count || 0;
    const totalPages = Math.ceil(total / limit);

    return {
      users: data || [],
      meta: {
        page,
        limit,
        total,
        total_pages: totalPages,
        has_next: page < totalPages,
        has_prev: page > 1
      }
    };
  }

  async getAdminStats(): Promise<{
    total_users: number;
    total_files: number;
    active_users_today: number;
    storage_used: number;
  }> {
    const today = new Date().toISOString().split('T')[0];

    const [usersCount, filesCount, activeUsersCount, storageQuery] = await Promise.all([
      adminSupabase.from('users').select('*', { count: 'exact', head: true }),
      adminSupabase.from('files').select('*', { count: 'exact', head: true }),
      adminSupabase.from('users').select('*', { count: 'exact', head: true })
        .gte('last_login', today),
      adminSupabase.from('files').select('size')
    ]);

    const storageUsed = storageQuery.data?.reduce((total, file) => total + (file.size || 0), 0) || 0;

    return {
      total_users: usersCount.count || 0,
      total_files: filesCount.count || 0,
      active_users_today: activeUsersCount.count || 0,
      storage_used: storageUsed
    };
  }
}

export const db = new DatabaseService();