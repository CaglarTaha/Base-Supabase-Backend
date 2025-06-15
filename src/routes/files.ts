import { Router, RequestHandler } from 'express';
import multer from 'multer';
import { fileController } from '@/controllers/fileController';
import { authenticate, requireOwnership } from '@/middleware/auth';
import { validate, validationSchemas, validateFileUpload } from '@/middleware/validation';

const router = Router();

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE || '10485760'), // 10MB default
    files: 10 // Maximum 10 files per upload
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = process.env.ALLOWED_FILE_TYPES?.split(',') || [
      'image/jpeg',
      'image/png',
      'image/gif',
      'application/pdf',
      'text/plain'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${file.mimetype} is not allowed`));
    }
  }
});

// File upload routes
router.post(
  '/upload',  authenticate,
  upload.single('file'),
  validateFileUpload,
  validate(validationSchemas.fileUpload),
  fileController.uploadFile as RequestHandler
);

router.post(
  '/upload-multiple',  authenticate,
  upload.array('files', 10),
  validateFileUpload,
  validate(validationSchemas.fileUpload),
  fileController.uploadMultipleFiles as RequestHandler
);

// File management routes
router.get(
  '/',
  authenticate,
  validate(validationSchemas.pagination),
  fileController.getUserFiles
);

router.get(
  '/stats',
  authenticate,
  fileController.getFileStats
);

router.get(
  '/:id',
  authenticate,
  validate(validationSchemas.uuid),
  requireOwnership('id'),
  fileController.getFileById
);

router.get(
  '/:id/download',
  authenticate,
  validate(validationSchemas.uuid),
  requireOwnership('id'),
  fileController.downloadFile
);

router.delete(
  '/:id',
  authenticate,
  validate(validationSchemas.uuid),
  requireOwnership('id'),
  fileController.deleteFile
);

export default router;