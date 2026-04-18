import express from 'express'
import db from '../config/database.js'
import { authMiddleware, optionalAuthMiddleware } from '../middleware/auth.js'
import { AppError } from '../middleware/error.js'
import multer from 'multer'
import path from 'path'
import fs from 'fs'
import { encryptFile, calculateFileMD5 } from '../utils/encryption.js'

const router = express.Router()

// 配置头像上传
const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, process.env.UPLOAD_DIR || './uploads')
    },
    filename: (req, file, cb) => {
      const uniqueName = `avatar_${req.user.id}_${Date.now()}${path.extname(file.originalname)}`
      cb(null, uniqueName)
    }
  }),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true)
    } else {
      cb(new AppError('只支持图片格式（JPG、PNG、GIF、WebP）', 400))
    }
  }
})

// 获取当前用户资料
router.get('/me', authMiddleware, async (req, res, next) => {
  try {
    const [users] = await db.query(`
      SELECT 
        u.id,
        u.username,
        u.email,
        u.bio,
        u.storage_used,
        u.created_at,
        r.id as role_id,
        r.name as role_name,
        r.display_name as role_display_name,
        r.storage_quota,
        f.filename as avatar_filename
      FROM users u
      JOIN roles r ON u.role_id = r.id
      LEFT JOIN files f ON u.avatar_file_id = f.id
      WHERE u.id = ?
    `, [req.user.id])

    if (users.length === 0) {
      throw new AppError('用户不存在', 404)
    }

    const user = users[0]
    
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        bio: user.bio,
        storageUsed: user.storage_used,
        storageQuota: user.storage_quota,
        avatarUrl: user.avatar_filename ? `/api/files/download/${user.avatar_filename}` : null,
        role: {
          id: user.role_id,
          name: user.role_name,
          displayName: user.role_display_name
        },
        createdAt: user.created_at
      }
    })
  } catch (error) {
    next(error)
  }
})

// 获取其他用户公开资料
router.get('/:userId', optionalAuthMiddleware, async (req, res, next) => {
  try {
    const { userId } = req.params

    const [users] = await db.query(`
      SELECT 
        u.id,
        u.username,
        u.bio,
        u.created_at,
        r.display_name as role_display_name,
        f.filename as avatar_filename,
        COUNT(DISTINCT files.id) as publicFileCount,
        SUM(files.downloads) as totalDownloads
      FROM users u
      JOIN roles r ON u.role_id = r.id
      LEFT JOIN files f ON u.avatar_file_id = f.id
      LEFT JOIN files ON files.user_id = u.id AND files.is_private = FALSE
      WHERE u.id = ?
      GROUP BY u.id
    `, [userId])

    if (users.length === 0) {
      throw new AppError('用户不存在', 404)
    }

    const user = users[0]
    
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        bio: user.bio,
        avatarUrl: user.avatar_filename ? `/api/files/download/${user.avatar_filename}` : null,
        role: user.role_display_name,
        publicFileCount: user.publicFileCount || 0,
        totalDownloads: user.totalDownloads || 0,
        createdAt: user.created_at
      }
    })
  } catch (error) {
    next(error)
  }
})

// 更新用户资料
router.put('/me', authMiddleware, async (req, res, next) => {
  try {
    const { username, bio } = req.body

    // 检查用户名是否已被占用
    if (username && username !== req.user.username) {
      const [existing] = await db.query('SELECT id FROM users WHERE username = ? AND id != ?', [username, req.user.id])
      if (existing.length > 0) {
        throw new AppError('用户名已被占用', 400)
      }
    }

    await db.query(
      'UPDATE users SET username = COALESCE(?, username), bio = ? WHERE id = ?',
      [username, bio, req.user.id]
    )

    res.json({ success: true, message: '资料已更新' })
  } catch (error) {
    next(error)
  }
})

// 修改密码
router.put('/me/password', authMiddleware, async (req, res, next) => {
  try {
    const { oldPassword, newPassword } = req.body

    if (!oldPassword || !newPassword) {
      throw new AppError('请提供旧密码和新密码', 400)
    }

    // 验证旧密码
    const [users] = await db.query('SELECT password FROM users WHERE id = ?', [req.user.id])
    if (users.length === 0 || users[0].password !== oldPassword) {
      throw new AppError('旧密码错误', 400)
    }

    // 更新密码
    await db.query('UPDATE users SET password = ? WHERE id = ?', [newPassword, req.user.id])

    res.json({ success: true, message: '密码已更新' })
  } catch (error) {
    next(error)
  }
})

// 上传头像
router.post('/me/avatar', authMiddleware, avatarUpload.single('avatar'), async (req, res, next) => {
  try {
    if (!req.file) {
      throw new AppError('请选择图片', 400)
    }

    const { filename, originalname, size, mimetype, path: filePath } = req.file

    // 加密文件
    const encryptedPath = filePath + '.enc'
    const iv = await encryptFile(filePath, encryptedPath)
    fs.renameSync(encryptedPath, filePath)

    // 计算 MD5
    const md5 = await calculateFileMD5(filePath, iv)

    // 保存到数据库
    const [result] = await db.query(
      'INSERT INTO files (user_id, filename, original_name, size, mime_type, is_private, encryption_iv, md5) VALUES (?, ?, ?, ?, ?, TRUE, ?, ?)',
      [req.user.id, filename, originalname, size, mimetype, iv, md5]
    )

    const fileId = result.insertId

    // 删除旧头像文件（如果存在）
    const [oldAvatar] = await db.query('SELECT avatar_file_id FROM users WHERE id = ?', [req.user.id])
    if (oldAvatar[0].avatar_file_id) {
      await db.query('DELETE FROM files WHERE id = ?', [oldAvatar[0].avatar_file_id])
    }

    // 更新用户头像
    await db.query('UPDATE users SET avatar_file_id = ? WHERE id = ?', [fileId, req.user.id])

    // 更新存储使用量
    await db.query('UPDATE users SET storage_used = storage_used + ? WHERE id = ?', [size, req.user.id])

    res.json({
      success: true,
      message: '头像已更新',
      avatarUrl: `/api/files/download/${filename}`
    })
  } catch (error) {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path)
    }
    next(error)
  }
})

export default router
