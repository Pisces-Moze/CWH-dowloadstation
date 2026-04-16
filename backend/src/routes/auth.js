import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { body, validationResult } from 'express-validator'
import db from '../config/database.js'
import { AppError } from '../middleware/errorHandler.js'

const router = express.Router()

// 注册
router.post('/signup',
  body('username').trim().isLength({ min: 3, max: 50 }).withMessage('用户名长度3-50字符'),
  body('email').isEmail().withMessage('请输入有效的邮箱'),
  body('password').isLength({ min: 6 }).withMessage('密码至少6位'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        throw new AppError(errors.array()[0].msg, 400)
      }

      const { username, email, password } = req.body

      // 检查用户是否存在
      const [existing] = await db.query(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        [username, email]
      )

      if (existing.length > 0) {
        throw new AppError('用户名或邮箱已存在', 400)
      }

      // 加密密码
      const hashedPassword = await bcrypt.hash(password, 10)

      // 插入用户
      await db.query(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashedPassword]
      )

      res.status(201).json({ success: true, message: '注册成功' })
    } catch (error) {
      next(error)
    }
  }
)

// 登录
router.post('/login',
  body('username').trim().notEmpty().withMessage('请输入用户名'),
  body('password').notEmpty().withMessage('请输入密码'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        throw new AppError(errors.array()[0].msg, 400)
      }

      const { username, password } = req.body

      // 查找用户
      const [users] = await db.query(
        'SELECT id, username, password FROM users WHERE username = ?',
        [username]
      )

      if (users.length === 0) {
        throw new AppError('用户名或密码错误', 401)
      }

      const user = users[0]

      // 验证密码
      const isValid = await bcrypt.compare(password, user.password)
      if (!isValid) {
        throw new AppError('用户名或密码错误', 401)
      }

      // 生成 JWT
      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      )

      res.json({
        success: true,
        token,
        username: user.username
      })
    } catch (error) {
      next(error)
    }
  }
)

export default router
