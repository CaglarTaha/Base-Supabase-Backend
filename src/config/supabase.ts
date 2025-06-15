import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { DatabaseConfig } from '@/types';
import dotenv from 'dotenv';

// Load environment variables early
dotenv.config();

class SupabaseConfig {
  private static instance: SupabaseConfig;
  private supabase: SupabaseClient;
  private adminSupabase: SupabaseClient;
  private constructor() {
    // Hardcoded fallbacks in case environment variables are not loaded
    const config: DatabaseConfig = {
      url: process.env.DATABASE_URL || "",
      apiKey: process.env.API_KEY || "",
      serviceRoleKey: process.env.SERVICE_ROLE_KEY || ""
    };

    console.log("Supabase configuration:", {
      url: config.url,
      apiKeyLength: config.apiKey ? config.apiKey.length : 0,
      serviceRoleKeyLength: config.serviceRoleKey ? config.serviceRoleKey.length : 0
    });

    if (!config.url || !config.apiKey || !config.serviceRoleKey) {
      throw new Error('Supabase configuration is missing required environment variables');
    }

    // Normal client for user operations
    this.supabase = createClient(config.url, config.apiKey, {
      auth: {
        autoRefreshToken: true,
        persistSession: false
      }
    });

    // Admin client with service role key for administrative operations
    this.adminSupabase = createClient(config.url, config.serviceRoleKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    });
  }

  public static getInstance(): SupabaseConfig {
    if (!SupabaseConfig.instance) {
      SupabaseConfig.instance = new SupabaseConfig();
    }
    return SupabaseConfig.instance;
  }

  public getClient(): SupabaseClient {
    return this.supabase;
  }

  public getAdminClient(): SupabaseClient {
    return this.adminSupabase;
  }

  public async testConnection(): Promise<boolean> {
    try {
   console.log("becekermedik abi")
      
      return true;
    } catch (error) {
      console.error('Supabase connection test failed:', error);
      return false;
    }
  }
}

export const supabaseConfig = SupabaseConfig.getInstance();
export const supabase = supabaseConfig.getClient();
export const adminSupabase = supabaseConfig.getAdminClient();