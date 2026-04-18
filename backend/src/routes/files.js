import express from 'express'
import multer from 'multer'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'
import db from '../config/database.js'
import { authMiddleware, optionalAuthMiddleware } from '../middleware/auth.js'
import { AppError } from '../middleware/errorHandler.js'
import { encryptFile, createDecryptStream, generateShareCode, isValidShareCode } from '../utils/encryption.js'

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
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 1024 * 1024 * 1024
  }
})

// 上传文件（支持公共/私人空间）
router.post('/upload', authMiddleware, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      throw new AppError('请选择文件', 400)
    }

    const { filename, originalname, size, mimetype, path: filePath } = req.file
    const isPrivate = req.body.isPrivate === 'true'

    // 加密文件
    const encryptedPath = filePath + '.enc'
    const iv = await encryptFile(filePath, encryptedPath)

    // 重命名加密文件
    fs.renameSync(encryptedPath, filePath)

    await db.query(
      'INSERT INTO files (user_id, filename, original_name, size, mime_type, is_private, encryption_iv) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [req.user.id, filename, originalname, size, mimetype, isPrivate, iv]
    )

    res.json({
      success: true,
      message: `上传成功（${isPrivate ? '私人空间' : '公共空间'}）`,
      file: {
        name: originalname,
        size,
        isPrivate
      }
    })
  } catch (error) {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path)
    }
    next(error)
  }
})

// 获取公共文件列表
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
      WHERE f.is_private = FALSE
      ORDER BY f.created_at DESC
      LIMIT 100
    `)

    res.json({ success: true, files })
  } catch (error) {
    next(error)
  }
})

// 获取我的私人文件（包括引用）
router.get('/private-files', authMiddleware, async (req, res, next) => {
  try {
    // 获取真实私人文件
    const [ownFiles] = await db.query(`
      SELECT 
        id,
        original_name as name,
        size,
        downloads,
        created_at as uploadTime,
        'own' as type
      FROM files
      WHERE user_id = ? AND is_private = TRUE
      ORDER BY created_at DESC
    `, [req.user.id])

    // 获取引用文件
    const [refFiles] = await db.query(`
      SELECT 
        fr.id,
        COALESCE(fr.reference_name, f.original_name) as name,
        f.size,
        fr.downloads,
        fr.created_at as uploadTime,
        'reference' as type,
        f.id as originalFileId
      FROM file_references fr
      JOIN files f ON fr.original_file_id = f.id
      WHERE fr.user_id = ?
      ORDER BY fr.created_at DESC
    `, [req.user.id])

    // 合并并按时间排序
    const allFiles = [...ownFiles, ...refFiles].sort((a, b) => 
      new Date(b.uploadTime) - new Date(a.uploadTime)
    )

    const [stats] = await db.query(`
      SELECT 
        (SELECT COUNT(*) FROM files WHERE user_id = ? AND is_private = TRUE) +
        (SELECT COUNT(*) FROM file_references WHERE user_id = ?) as totalFiles,
        (SELECT COALESCE(SUM(size), 0) FROM files WHERE user_id = ? AND is_private = TRUE) as totalSize
    `, [req.user.id, req.user.id, req.user.id])

    res.json({
      success: true,
      files: allFiles,
      stats: {
        totalFiles: stats[0].totalFiles || 0,
        totalSize: formatBytes(stats[0].totalSize || 0)
      }
    })
  } catch (error) {
    next(error)
  }
})

// 转存公共文件到私人空间（引用）
router.post('/save-to-private/:fileId', authMiddleware, async (req, res, next) => {
  try {
    const { fileId } = req.params
    const { referenceName } = req.body

    // 检查文件是否存在且为公共文件
    const [files] = await db.query(
      'SELECT * FROM files WHERE id = ? AND is_private = FALSE',
      [fileId]
    )

    if (files.length === 0) {
      throw new AppError('文件不存在或不是公共文件', 404)
    }

    // 检查是否已经转存过
    const [existing] = await db.query(
      'SELECT * FROM file_references WHERE user_id = ? AND original_file_id = ?',
      [req.user.id, fileId]
    )

    if (existing.length > 0) {
      throw new AppError('已经转存过此文件', 400)
    }

    // 创建引用
    await db.query(
      'INSERT INTO file_references (user_id, original_file_id, reference_name) VALUES (?, ?, ?)',
      [req.user.id, fileId, referenceName || null]
    )

    res.json({
      success: true,
      message: '转存成功（不占用额外空间）'
    })
  } catch (error) {
    next(error)
  }
})

// 获取我的公共文件
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
      WHERE user_id = ? AND is_private = FALSE
      ORDER BY created_at DESC
    `, [req.user.id])

    const [stats] = await db.query(`
      SELECT 
        COUNT(*) as totalFiles,
        SUM(size) as totalSize,
        SUM(downloads) as downloads
      FROM files
      WHERE user_id = ? AND is_private = FALSE
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

// 下载文件（带权限验证）
router.get('/download/:filename', optionalAuthMiddleware, async (req, res, next) => {
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

    // 私人文件权限检查
    if (file.is_private) {
      if (!req.user || req.user.id !== file.user_id) {
        throw new AppError('无权访问此文件', 403)
      }
    }

    const filePath = path.join(process.env.UPLOAD_DIR || './uploads', file.filename)

    if (!fs.existsSync(filePath)) {
      throw new AppError('文件不存在', 404)
    }

    // 增加下载次数
    await db.query('UPDATE files SET downloads = downloads + 1 WHERE id = ?', [file.id])

    // 解密并发送文件
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.original_name)}"`)
    res.setHeader('Content-Type', file.mime_type || 'application/octet-stream')

    const decryptStream = createDecryptStream(file.encryption_iv)
    fs.createReadStream(filePath).pipe(decryptStream).pipe(res)
  } catch (error) {
    next(error)
  }
})

// 下载引用文件
router.get('/download-ref/:refId', authMiddleware, async (req, res, next) => {
  try {
    const { refId } = req.params

    // 获取引用信息
    const [refs] = await db.query(
      'SELECT * FROM file_references WHERE id = ? AND user_id = ?',
      [refId, req.user.id]
    )

    if (refs.length === 0) {
      throw new AppError('引用不存在或无权限', 404)
    }

    const ref = refs[0]

    // 获取原始文件
    const [files] = await db.query(
      'SELECT * FROM files WHERE id = ?',
      [ref.original_file_id]
    )

    if (files.length === 0) {
      throw new AppError('原始文件已被删除', 404)
    }

    const file = files[0]
    const filePath = path.join(process.env.UPLOAD_DIR || './uploads', file.filename)

    if (!fs.existsSync(filePath)) {
      throw new AppError('文件不存在', 404)
    }

    // 增加引用的下载次数（不增加原文件的）
    await db.query('UPDATE file_references SET downloads = downloads + 1 WHERE id = ?', [ref.id])

    // 解密并发送文件
    const displayName = ref.reference_name || file.original_name
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(displayName)}"`)
    res.setHeader('Content-Type', file.mime_type || 'application/octet-stream')

    const decryptStream = createDecryptStream(file.encryption_iv)
    fs.createReadStream(filePath).pipe(decryptStream).pipe(res)
  } catch (error) {
    next(error)
  }
})

// 创建分享链接
router.post('/share/:fileId', authMiddleware, async (req, res, next) => {
  try {
    const { fileId } = req.params
    const { password, expiresIn, maxDownloads } = req.body

    const [files] = await db.query(
      'SELECT * FROM files WHERE id = ? AND user_id = ?',
      [fileId, req.user.id]
    )

    if (files.length === 0) {
      throw new AppError('文件不存在或无权限', 404)
    }

    const file = files[0]

    // 私人文件不能分享
    if (file.is_private) {
      throw new AppError('私人文件不支持分享', 400)
    }

    const shareCode = generateShareCode()
    let expiresAt = null

    if (expiresIn) {
      expiresAt = new Date(Date.now() + expiresIn * 60 * 60 * 1000)
    }

    await db.query(
      'INSERT INTO share_links (file_id, share_code, password, expires_at, max_downloads) VALUES (?, ?, ?, ?, ?)',
      [fileId, shareCode, password || null, expiresAt, maxDownloads || 0]
    )

    const shareUrl = `${req.protocol}://${req.get('host')}/api/files/s/${shareCode}`

    res.json({
      success: true,
      shareUrl,
      shareCode,
      expiresAt
    })
  } catch (error) {
    next(error)
  }
})

// 通过分享链接下载
router.get('/s/:shareCode', async (req, res, next) => {
  try {
    const { shareCode } = req.params
    const { password } = req.query

    if (!isValidShareCode(shareCode)) {
      throw new AppError('无效的分享链接', 400)
    }

    const [shares] = await db.query(
      'SELECT * FROM share_links WHERE share_code = ?',
      [shareCode]
    )

    if (shares.length === 0) {
      throw new AppError('分享链接不存在', 404)
    }

    const share = shares[0]

    // 检查是否过期
    if (share.expires_at && new Date(share.expires_at) < new Date()) {
      throw new AppError('分享链接已过期', 410)
    }

    // 检查下载次数限制
    if (share.max_downloads > 0 && share.downloads >= share.max_downloads) {
      throw new AppError('下载次数已达上限', 403)
    }

    // 检查密码
    if (share.password && share.password !== password) {
      throw new AppError('密码错误', 401)
    }

    const [files] = await db.query(
      'SELECT * FROM files WHERE id = ?',
      [share.file_id]
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
    await db.query('UPDATE share_links SET downloads = downloads + 1 WHERE id = ?', [share.id])
    await db.query('UPDATE files SET downloads = downloads + 1 WHERE id = ?', [file.id])

    // 解密并发送文件
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.original_name)}"`)
    res.setHeader('Content-Type', file.mime_type || 'application/octet-stream')

    const decryptStream = createDecryptStream(file.encryption_iv)
    fs.createReadStream(filePath).pipe(decryptStream).pipe(res)
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

    await db.query('DELETE FROM files WHERE id = ?', [id])

    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath)
    }

    res.json({ success: true, message: '删除成功' })
  } catch (error) {
    next(error)
  }
})

// 删除分享链接
router.delete('/share/:shareCode', authMiddleware, async (req, res, next) => {
  try {
    const { shareCode } = req.params

    const [shares] = await db.query(`
      SELECT sl.* FROM share_links sl
      JOIN files f ON sl.file_id = f.id
      WHERE sl.share_code = ? AND f.user_id = ?
    `, [shareCode, req.user.id])

    if (shares.length === 0) {
      throw new AppError('分享链接不存在或无权限', 404)
    }

    await db.query('DELETE FROM share_links WHERE share_code = ?', [shareCode])

    res.json({ success: true, message: '分享链接已删除' })
  } catch (error) {
    next(error)
  }
})

// 删除引用文件
router.delete('/reference/:refId', authMiddleware, async (req, res, next) => {
  try {
    const { refId } = req.params

    const [refs] = await db.query(
      'SELECT * FROM file_references WHERE id = ? AND user_id = ?',
      [refId, req.user.id]
    )

    if (refs.length === 0) {
      throw new AppError('引用不存在或无权限', 404)
    }

    await db.query('DELETE FROM file_references WHERE id = ?', [refId])

    res.json({ success: true, message: '已从私人空间移除（原文件保留）' })
  } catch (error) {
    next(error)
  }
})

function formatBytes(bytes) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

export default router
