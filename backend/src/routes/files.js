import express from 'express'
import multer from 'multer'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'
import db from '../config/database.js'
import { authMiddleware } from '../middleware/auth.js'
import { AppError } from '../middleware/errorHandler.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const router = express.Router()

// 配置文件上传
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = process.env.UPLOAD_DIR || './uploads'
    cb(null, uploadDir)
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, uniqueSuffix + '-' + Buffer.from(file.originalname, 'latin1').toString('utf8'))
  }
})

const upload = multer({
  storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 1024 * 1024 * 1024 // 1GB 默认
  }
})

// 上传文件
router.post('/upload', authMiddleware, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      throw new AppError('请选择文件', 400)
    }

    const { filename, originalname, size, mimetype } = req.file

    await db.query(
      'INSERT INTO files (user_id, filename, original_name, size, mime_type) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, filename, originalname, size, mimetype]
    )

    res.json({
      success: true,
      message: '上传成功',
      file: {
        name: originalname,
        size
      }
    })
  } catch (error) {
    // 删除已上传的文件
    if (req.file) {
      fs.unlinkSync(req.file.path)
    }
    next(error)
  }
})

// 获取文件列表
router.get('/files', async (req, res, next) => {
  try {
    const [files] = await db.query(`
      SELECT 
        f.id,
        f.original_name as name,
        f.size,
        f.downloads,
        f.created_at as uploadTime,
        u.username as uploader
      FROM files f
      JOIN users u ON f.user_id = u.id
      ORDER BY f.created_at DESC
      LIMIT 100
    `)

    res.json({ success: true, files })
  } catch (error) {
    next(error)
  }
})

// 获取我的文件
router.get('/my-files', authMiddleware, async (req, res, next) => {
  try {
    const [files] = await db.query(`
      SELECT 
        id,
        original_name as name,
        size,
        downloads,
        created_at as uploadTime
      FROM files
      WHERE user_id = ?
      ORDER BY created_at DESC
    `, [req.user.id])

    const [stats] = await db.query(`
      SELECT 
        COUNT(*) as totalFiles,
        SUM(size) as totalSize,
        SUM(downloads) as downloads
      FROM files
      WHERE user_id = ?
    `, [req.user.id])

    res.json({
      success: true,
      files,
      stats: {
        totalFiles: stats[0].totalFiles || 0,
        totalSize: formatBytes(stats[0].totalSize || 0),
        downloads: stats[0].downloads || 0
      }
    })
  } catch (error) {
    next(error)
  }
})

// 下载文件
router.get('/download/:filename', async (req, res, next) => {
  try {
    const { filename } = req.params

    const [files] = await db.query(
      'SELECT * FROM files WHERE filename = ?',
      [filename]
    )

    if (files.length === 0) {
      throw new AppError('文件不存在', 404)
    }

    const file = files[0]
    const filePath = path.join(process.env.UPLOAD_DIR || './uploads', file.filename)

    if (!fs.existsSync(filePath)) {
      throw new AppError('文件不存在', 404)
    }

    // 增加下载次数
    await db.query('UPDATE files SET downloads = downloads + 1 WHERE id = ?', [file.id])

    res.download(filePath, file.original_name)
  } catch (error) {
    next(error)
  }
})

// 删除文件
router.delete('/files/:id', authMiddleware, async (req, res, next) => {
  try {
    const { id } = req.params

    const [files] = await db.query(
      'SELECT * FROM files WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    )

    if (files.length === 0) {
      throw new AppError('文件不存在或无权限', 404)
    }

    const file = files[0]
    const filePath = path.join(process.env.UPLOAD_DIR || './uploads', file.filename)

    // 删除数据库记录
    await db.query('DELETE FROM files WHERE id = ?', [id])

    // 删除文件
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath)
    }

    res.json({ success: true, message: '删除成功' })
  } catch (error) {
    next(error)
  }
})

// 辅助函数：格式化文件大小
function formatBytes(bytes) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

export default router
