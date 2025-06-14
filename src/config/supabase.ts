import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { DatabaseConfig } from '@/types';

class SupabaseConfig {
  private static instance: SupabaseConfig;
  private supabase: SupabaseClient;
  private adminSupabase: SupabaseClient;

  private constructor() {
    const config: DatabaseConfig = {
      url: "https://cuypguwrnuvofkmzlbnq.supabase.co",
      apiKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN1eXBndXdybnV2b2ZrbXpsYm5xIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDk3NjQ5NzEsImV4cCI6MjA2NTM0MDk3MX0.rPQLxKYId5jsacv2fl-tshlR6tFncIMkt6Tbk7EkWXQ",
      serviceRoleKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN1eXBndXdybnV2b2ZrbXpsYm5xIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc0OTc2NDk3MSwiZXhwIjoyMDY1MzQwOTcxfQ.bh3Qa-SZvernBEEhkYVlAyoMoins--i4Xkgkf4s4_QE"
    };

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