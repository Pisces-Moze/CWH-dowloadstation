import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { body, validationResult } from 'express-validator'
import db from '../config/database.js'
import { AppError } from '../middleware/errorHandler.js'
import { sendVerificationCode, generateVerificationCode } from '../utils/email.js'

const router = express.Router()

// 发送验证码
router.post('/send-code',
  body('email').isEmail().withMessage('请输入有效的邮箱'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        throw new AppError(errors.array()[0].msg, 400)
      }

      const { email } = req.body

      // 检查邮箱是否已注册
      const [existing] = await db.query(
        'SELECT id FROM users WHERE email = ?',
        [email]
      )

      if (existing.length > 0) {
        throw new AppError('该邮箱已被注册', 400)
      }

      // 生成验证码
      const code = generateVerificationCode()
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000) // 5分钟后过期

      // 删除旧的验证码
      await db.query('DELETE FROM email_verifications WHERE email = ?', [email])

      // 保存验证码
      await db.query(
        'INSERT INTO email_verifications (email, code, expires_at) VALUES (?, ?, ?)',
        [email, code, expiresAt]
      )

      // 发送邮件
      const result = await sendVerificationCode(email, code)
      
      if (!result.success) {
        throw new AppError('验证码发送失败，请检查邮箱配置', 500)
      }

      res.json({ success: true, message: '验证码已发送到您的邮箱' })
    } catch (error) {
      next(error)
    }
  }
)

// 注册
router.post('/register',
  body('username').trim().isLength({ min: 3, max: 50 }).withMessage('用户名长度3-50字符'),
  body('email').isEmail().withMessage('请输入有效的邮箱'),
  body('password').isLength({ min: 6 }).withMessage('密码至少6位'),
  body('code').trim().isLength({ min: 6, max: 6 }).withMessage('请输入验证码'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        throw new AppError(errors.array()[0].msg, 400)
      }

      const { username, email, password, code } = req.body

      // 验证验证码
      const [verifications] = await db.query(
        'SELECT * FROM email_verifications WHERE email = ? AND code = ? AND expires_at > NOW()',
        [email, code]
      )

      if (verifications.length === 0) {
        throw new AppError('验证码错误或已过期', 400)
      }

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
      const [result] = await db.query(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashedPassword]
      )

      const userId = result.insertId

      // 删除已使用的验证码
      await db.query('DELETE FROM email_verifications WHERE email = ?', [email])

      // 生成 JWT
      const token = jwt.sign(
        { id: userId, username },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      )

      res.status(201).json({ 
        success: true, 
        message: '注册成功',
        token,
        username
      })
    } catch (error) {
      next(error)
    }
  }
)

// 登录
router.post('/login',
  body('email').trim().notEmpty().withMessage('请输入邮箱或用户名'),
  body('password').notEmpty().withMessage('请输入密码'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        throw new AppError(errors.array()[0].msg, 400)
      }

      const { email, password } = req.body

      // 查找用户（支持邮箱或用户名登录）
      const [users] = await db.query(
        'SELECT id, username, email, password FROM users WHERE email = ? OR username = ?',
        [email, email]
      )

      if (users.length === 0) {
        throw new AppError('邮箱/用户名或密码错误', 401)
      }

      const user = users[0]

      // 验证密码
      const isValid = await bcrypt.compare(password, user.password)
      if (!isValid) {
        throw new AppError('邮箱/用户名或密码错误', 401)
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
