import express from 'express'
import db from '../config/database.js'
import { authMiddleware } from '../middleware/auth.js'
import { requireAdmin, requireViewStats } from '../middleware/permission.js'
import { AppError } from '../middleware/error.js'

const router = express.Router()

// 获取统计数据（管理员）
router.get('/stats', authMiddleware, requireViewStats, async (req, res, next) => {
  try {
    // 总用户数
    const [userCount] = await db.query('SELECT COUNT(*) as count FROM users')
    
    // 总文件数和总大小
    const [fileStats] = await db.query(`
      SELECT 
        COUNT(*) as totalFiles,
        SUM(size) as totalSize,
        SUM(downloads) as totalDownloads
      FROM files
    `)
    
    // 当前在线人数（5分钟内活跃）
    const [onlineCount] = await db.query(`
      SELECT COUNT(DISTINCT session_id) as count 
      FROM visitor_sessions 
      WHERE last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
    `)
    
    // 文件下载排行榜（Top 10）
    const [topFiles] = await db.query(`
      SELECT 
        f.id,
        f.original_name as name,
        f.downloads,
        u.username as uploader
      FROM files f
      JOIN users u ON f.user_id = u.id
      WHERE f.is_private = FALSE
      ORDER BY f.downloads DESC
      LIMIT 10
    `)
    
    // 用户上传排行榜（Top 10）
    const [topUploaders] = await db.query(`
      SELECT 
        u.id,
        u.username,
        COUNT(f.id) as fileCount,
        SUM(f.size) as totalSize,
        SUM(f.downloads) as totalDownloads
      FROM users u
      LEFT JOIN files f ON u.id = f.user_id AND f.is_private = FALSE
      GROUP BY u.id
      ORDER BY fileCount DESC
      LIMIT 10
    `)
    
    // 最近7天下载趋势
    const [downloadTrend] = await db.query(`
      SELECT 
        DATE(downloaded_at) as date,
        COUNT(*) as count
      FROM download_logs
      WHERE downloaded_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
      GROUP BY DATE(downloaded_at)
      ORDER BY date ASC
    `)

    res.json({
      success: true,
      stats: {
        totalUsers: userCount[0].count,
        totalFiles: fileStats[0].totalFiles || 0,
        totalSize: fileStats[0].totalSize || 0,
        totalDownloads: fileStats[0].totalDownloads || 0,
        onlineUsers: onlineCount[0].count || 0,
        topFiles,
        topUploaders,
        downloadTrend
      }
    })
  } catch (error) {
    next(error)
  }
})

// 获取所有用户列表（管理员）
router.get('/users', authMiddleware, requireAdmin, async (req, res, next) => {
  try {
    const [users] = await db.query(`
      SELECT 
        u.id,
        u.username,
        u.email,
        u.storage_used,
        u.created_at,
        r.id as role_id,
        r.name as role_name,
        r.display_name as role_display_name,
        r.storage_quota
      FROM users u
      JOIN roles r ON u.role_id = r.id
      ORDER BY u.created_at DESC
    `)

    res.json({ success: true, users })
  } catch (error) {
    next(error)
  }
})

// 更新用户角色（管理员）
router.put('/users/:userId/role', authMiddleware, requireAdmin, async (req, res, next) => {
  try {
    const { userId } = req.params
    const { roleId } = req.body

    // 不能修改自己的角色
    if (parseInt(userId) === req.user.id) {
      throw new AppError('不能修改自己的角色', 400)
    }

    // 检查角色是否存在
    const [roles] = await db.query('SELECT * FROM roles WHERE id = ?', [roleId])
    if (roles.length === 0) {
      throw new AppError('角色不存在', 404)
    }

    await db.query('UPDATE users SET role_id = ? WHERE id = ?', [roleId, userId])

    res.json({ success: true, message: '角色已更新' })
  } catch (error) {
    next(error)
  }
})

// 更新用户存储配额（管理员）
router.put('/users/:userId/quota', authMiddleware, requireAdmin, async (req, res, next) => {
  try {
    const { userId } = req.params
    const { quota } = req.body

    if (!quota || quota < 0) {
      throw new AppError('无效的配额值', 400)
    }

    // 更新用户角色的存储配额（如果是自定义配额，需要创建新角色或直接修改）
    // 这里简化处理：直接更新角色的配额
    await db.query(`
      UPDATE roles r
      JOIN users u ON r.id = u.role_id
      SET r.storage_quota = ?
      WHERE u.id = ?
    `, [quota, userId])

    res.json({ success: true, message: '存储配额已更新' })
  } catch (error) {
    next(error)
  }
})

// 删除用户（管理员）
router.delete('/users/:userId', authMiddleware, requireAdmin, async (req, res, next) => {
  try {
    const { userId } = req.params

    // 不能删除自己
    if (parseInt(userId) === req.user.id) {
      throw new AppError('不能删除自己', 400)
    }

    await db.query('DELETE FROM users WHERE id = ?', [userId])

    res.json({ success: true, message: '用户已删除' })
  } catch (error) {
    next(error)
  }
})

// 获取所有角色（管理员）
router.get('/roles', authMiddleware, requireAdmin, async (req, res, next) => {
  try {
    const [roles] = await db.query('SELECT * FROM roles ORDER BY id ASC')
    res.json({ success: true, roles })
  } catch (error) {
    next(error)
  }
})

// 更新角色权限（管理员）
router.put('/roles/:roleId', authMiddleware, requireAdmin, async (req, res, next) => {
  try {
    const { roleId } = req.params
    const { displayName, storageQuota, canDeletePublicFiles, canManageUsers, canViewStats } = req.body

    // 不能修改管理员角色的核心权限
    if (parseInt(roleId) === 1) {
      throw new AppError('不能修改管理员角色的核心权限', 400)
    }

    await db.query(`
      UPDATE roles 
      SET display_name = ?,
          storage_quota = ?,
          can_delete_public_files = ?,
          can_manage_users = ?,
          can_view_stats = ?
      WHERE id = ?
    `, [displayName, storageQuota, canDeletePublicFiles, canManageUsers, canViewStats, roleId])

    res.json({ success: true, message: '角色已更新' })
  } catch (error) {
    next(error)
  }
})

export default router
