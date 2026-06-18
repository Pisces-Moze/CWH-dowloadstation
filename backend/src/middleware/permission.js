import db from '../config/database.js'
import { AppError } from './error.js'

// 检查用户角色权限
export async function checkPermission(requiredPermission) {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError('未登录', 401)
      }

      const [users] = await db.query(`
        SELECT r.* FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.id = ?
      `, [req.user.id])

      if (users.length === 0) {
        throw new AppError('用户不存在', 404)
      }

      const role = users[0]
      req.user.role = role

      // 检查权限
      if (!role[requiredPermission]) {
        throw new AppError('权限不足', 403)
      }

      next()
    } catch (error) {
      next(error)
    }
  }
}

// 检查是否为管理员
export const requireAdmin = async (req, res, next) => {
  return checkPermission('can_manage_users')(req, res, next)
}

// 检查是否可以查看统计
export const requireViewStats = async (req, res, next) => {
  return checkPermission('can_view_stats')(req, res, next)
}

// 检查是否可以删除公共文件
export const requireDeletePublicFiles = async (req, res, next) => {
  return checkPermission('can_delete_public_files')(req, res, next)
}

// 检查存储空间配额
export async function checkStorageQuota(req, res, next) {
  try {
    if (!req.user) {
      throw new AppError('未登录', 401)
    }

    const [users] = await db.query(`
      SELECT u.storage_used, r.storage_quota
      FROM users u
      JOIN roles r ON u.role_id = r.id
      WHERE u.id = ?
    `, [req.user.id])

    if (users.length === 0) {
      throw new AppError('用户不存在', 404)
    }

    const { storage_used, storage_quota } = users[0]
    
    // 如果有文件上传，检查是否超出配额
    if (req.file) {
      if (storage_used + req.file.size > storage_quota) {
        throw new AppError('存储空间不足', 400)
      }
    }

    req.user.storageUsed = storage_used
    req.user.storageQuota = storage_quota

    next()
  } catch (error) {
    next(error)
  }
}
