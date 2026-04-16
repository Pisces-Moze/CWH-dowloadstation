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

// 中间件
import { errorHandler } from './middleware/errorHandler.js'

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

// 路由
app.use('/api/auth', authRoutes)
app.use('/api', fileRoutes)

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
