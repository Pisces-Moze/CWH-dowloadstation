import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import morgan from 'morgan'
import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'
import path from 'path'
import { fileURLToPath } from 'url'
import fs from 'fs'

// 路由
import authRoutes from './routes/auth.js'
import fileRoutes from './routes/files.js'
import adminRoutes from './routes/admin.js'
import profileRoutes from './routes/profile.js'

// 中间件
import { errorHandler } from './middleware/errorHandler.js'
import db from './config/database.js'

dotenv.config()

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = process.env.PORT || 1145

// 中间件
app.use(helmet())
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? 'https://yourdomain.com' 
    : 'http://localhost:3000',
  credentials: true
}))
app.use(morgan('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

// 创建必要的目录
const uploadDir = process.env.UPLOAD_DIR || './uploads'
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true })
}

// 访客追踪中间件
app.use(async (req, res, next) => {
  try {
    const sessionId = req.cookies.session_id || require('crypto').randomBytes(32).toString('hex')
    const userId = req.user ? req.user.id : null
    const ipAddress = req.ip || req.connection.remoteAddress
    const userAgent = req.get('user-agent')

    // 设置 session cookie
    if (!req.cookies.session_id) {
      res.cookie('session_id', sessionId, { maxAge: 24 * 60 * 60 * 1000, httpOnly: true })
    }

    // 更新或创建访客会话
    await db.query(`
      INSERT INTO visitor_sessions (session_id, user_id, ip_address, user_agent)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE 
        user_id = VALUES(user_id),
        last_activity = CURRENT_TIMESTAMP
    `, [sessionId, userId, ipAddress, userAgent])

    next()
  } catch (error) {
    // 访客追踪失败不影响主流程
    next()
  }
})

// 路由
app.use('/api/auth', authRoutes)
app.use('/api/files', fileRoutes)
app.use('/api/admin', adminRoutes)
app.use('/api/profile', profileRoutes)

// 健康检查
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() })
})

// 错误处理
app.use(errorHandler)

// 启动服务器
if (process.env.NODE_ENV === 'production' && process.env.SSL_KEY_PATH && process.env.SSL_CERT_PATH) {
  // HTTPS
  import('https').then(https => {
    const options = {
      key: fs.readFileSync(process.env.SSL_KEY_PATH),
      cert: fs.readFileSync(process.env.SSL_CERT_PATH)
    }
    https.createServer(options, app).listen(PORT, () => {
      console.log(`🔒 HTTPS Server running on port ${PORT}`)
    })
  })
} else {
  // HTTP
  app.listen(PORT, () => {
    console.log(`🚀 HTTP Server running on port ${PORT}`)
    console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`)
  })
}

export default app
