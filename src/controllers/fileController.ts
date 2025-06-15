import { Response } from 'express';
import { AuthenticatedRequest, FileUploadRequest, PaginationQuery } from '@/types';
import { db } from '@/config/database';
import { supabase } from '@/config/supabase';
import { 
  responseUtils, 
  fileUtils, 
  paginationUtils, 
  logger 
} from '@/utils/helpers';

export class FileController {  // Upload single file
  async uploadFile(req: FileUploadRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      if (!req.file) {
        return res.status(400).json(
          responseUtils.error('No file uploaded')
        );
      }

      const file = req.file;
      const folder = req.query.folder as string || 'uploads';

      // Generate unique filename
      const fileName = fileUtils.generateFileName(file.originalname);
      const filePath = `${folder}/${req.user.id}/${fileName}`;

      // Upload to Supabase Storage
      const { data: uploadData, error: uploadError } = await supabase.storage
        .from('files')
        .upload(filePath, file.buffer, {
          contentType: file.mimetype,
          upsert: false
        });

      if (uploadError) {
        logger.error('Supabase upload error:', uploadError);
        return res.status(500).json(
          responseUtils.error('File upload failed')
        );
      }

      // Get public URL
      const { data: urlData } = supabase.storage
        .from('files')
        .getPublicUrl(filePath);

      // Save file record to database
      const fileRecord = await db.createFileRecord({
        user_id: req.user.id,
        filename: fileName,
        original_name: file.originalname,
        mime_type: file.mimetype,
        size: file.size,
        url: urlData.publicUrl
      });

      logger.info(`File uploaded by user ${req.user.email}: ${file.originalname}`);

      res.status(201).json(
        responseUtils.success(fileRecord, 'File uploaded successfully')
      );

    } catch (error) {
      logger.error('File upload error:', error);
      res.status(500).json(
        responseUtils.error('File upload failed')
      );
    }
  }

  // Upload multiple files
  async uploadMultipleFiles(req: FileUploadRequest, res: Response): Promise<Response | void> {
    try {      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const files = req.files as Express.Multer.File[];
      if (!files || files.length === 0) {
        return res.status(400).json(
          responseUtils.error('No files uploaded')
        );
      }

      const folder = req.query.folder as string || 'uploads';
      const uploadedFiles = [];
      const errors = [];

      // Process each file
      for (const file of files) {
        try {
          const fileName = fileUtils.generateFileName(file.originalname);
          const filePath = `${folder}/${req.user.id}/${fileName}`;

          // Upload to Supabase Storage
          const { data: uploadData, error: uploadError } = await supabase.storage
            .from('files')
            .upload(filePath, file.buffer, {
              contentType: file.mimetype,
              upsert: false
            });

          if (uploadError) {
            errors.push(`Failed to upload ${file.originalname}: ${uploadError.message}`);
            continue;
          }

          // Get public URL
          const { data: urlData } = supabase.storage
            .from('files')
            .getPublicUrl(filePath);

          // Save file record to database
          const fileRecord = await db.createFileRecord({
            user_id: req.user.id,
            filename: fileName,
            original_name: file.originalname,
            mime_type: file.mimetype,
            size: file.size,
            url: urlData.publicUrl
          });

          uploadedFiles.push(fileRecord);

        } catch (error) {
          errors.push(`Failed to upload ${file.originalname}: ${error}`);
        }
      }

      logger.info(`Multiple files uploaded by user ${req.user.email}: ${uploadedFiles.length} successful, ${errors.length} failed`);

      res.status(201).json(
        responseUtils.success({
          uploaded_files: uploadedFiles,
          errors: errors.length > 0 ? errors : undefined,
          summary: {
            total: files.length,
            successful: uploadedFiles.length,
            failed: errors.length
          }
        }, `${uploadedFiles.length} files uploaded successfully`)
      );

    } catch (error) {
      logger.error('Multiple file upload error:', error);
      res.status(500).json(
        responseUtils.error('Multiple file upload failed')
      );
    }
  }

  // Get user's files with pagination
  async getUserFiles(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
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

      const result = await db.getUserFiles(req.user.id, pagination);

      res.json(
        responseUtils.paginated(result.files, result.meta, 'Files retrieved successfully')
      );

    } catch (error) {
      logger.error('Get user files error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve files')
      );
    }
  }

  // Get file by ID
  async getFileById(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const fileId = req.params.id;
      const file = await db.getFileById(fileId);

      if (!file) {
        return res.status(404).json(
          responseUtils.error('File not found')
        );
      }

      // Check if user owns the file or is admin
      if (file.user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json(
          responseUtils.error('Access denied')
        );
      }

      res.json(
        responseUtils.success(file, 'File retrieved successfully')
      );

    } catch (error) {
      logger.error('Get file error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve file')
      );
    }
  }

  // Download file
  async downloadFile(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const fileId = req.params.id;
      const file = await db.getFileById(fileId);

      if (!file) {
        return res.status(404).json(
          responseUtils.error('File not found')
        );
      }

      // Check if user owns the file or is admin
      if (file.user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json(
          responseUtils.error('Access denied')
        );
      }

      // Extract file path from URL
      const urlParts = file.url.split('/');
      const bucketIndex = urlParts.findIndex(part => part === 'files');
      const filePath = urlParts.slice(bucketIndex + 1).join('/');

      // Download from Supabase Storage
      const { data, error } = await supabase.storage
        .from('files')
        .download(filePath);

      if (error) {
        logger.error('Supabase download error:', error);
        return res.status(500).json(
          responseUtils.error('File download failed')
        );
      }

      // Set appropriate headers
      res.setHeader('Content-Type', file.mime_type);
      res.setHeader('Content-Disposition', `attachment; filename="${file.original_name}"`);
      res.setHeader('Content-Length', file.size.toString());

      // Convert blob to buffer and send
      const buffer = Buffer.from(await data.arrayBuffer());
      res.send(buffer);

      logger.info(`File downloaded by user ${req.user.email}: ${file.original_name}`);

    } catch (error) {
      logger.error('Download file error:', error);
      res.status(500).json(
        responseUtils.error('File download failed')
      );
    }
  }

  // Delete file
  async deleteFile(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const fileId = req.params.id;
      const file = await db.getFileById(fileId);

      if (!file) {
        return res.status(404).json(
          responseUtils.error('File not found')
        );
      }

      // Check if user owns the file or is admin
      if (file.user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json(
          responseUtils.error('Access denied')
        );
      }

      // Extract file path from URL
      const urlParts = file.url.split('/');
      const bucketIndex = urlParts.findIndex(part => part === 'files');
      const filePath = urlParts.slice(bucketIndex + 1).join('/');

      // Delete from Supabase Storage
      const { error: storageError } = await supabase.storage
        .from('files')
        .remove([filePath]);

      if (storageError) {
        logger.error('Supabase delete error:', storageError);
        // Continue to delete database record even if storage delete fails
      }

      // Delete file record from database
      await db.deleteFile(fileId);

      logger.info(`File deleted by user ${req.user.email}: ${file.original_name}`);

      res.json(
        responseUtils.success(null, 'File deleted successfully')
      );

    } catch (error) {
      logger.error('Delete file error:', error);
      res.status(500).json(
        responseUtils.error('File deletion failed')
      );
    }
  }

  // Get file statistics for user
  async getFileStats(req: AuthenticatedRequest, res: Response): Promise<Response | void> {
    try {
      if (!req.user) {
        return res.status(401).json(
          responseUtils.error('User not authenticated')
        );
      }

      const { files } = await db.getUserFiles(req.user.id, { page: 1, limit: 1000 });

      const stats = {
        total_files: files.length,
        total_size: files.reduce((sum, file) => sum + file.size, 0),
        total_size_formatted: fileUtils.formatFileSize(
          files.reduce((sum, file) => sum + file.size, 0)
        ),
        file_types: files.reduce((acc, file) => {
          acc[file.mime_type] = (acc[file.mime_type] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
        recent_uploads: files
          .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
          .slice(0, 5)
      };

      res.json(
        responseUtils.success(stats, 'File statistics retrieved successfully')
      );

    } catch (error) {
      logger.error('Get file stats error:', error);
      res.status(500).json(
        responseUtils.error('Failed to retrieve file statistics')
      );
    }
  }
}

export const fileController = new FileController();