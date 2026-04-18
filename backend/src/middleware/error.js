// 自定义错误类
export class AppError extends Error {
  constructor(message, statusCode = 500) {
    super(message)
    this.statusCode = statusCode
    this.isOperational = true
    Error.captureStackTrace(this, this.constructor)
  }
}

// 错误处理中间件
export function errorHandler(err, req, res, next) {
  let { statusCode = 500, message } = err

  // 开发环境打印错误堆栈
  if (process.env.NODE_ENV === 'development') {
    console.error('Error:', err)
  }

  // 生产环境不暴露内部错误
  if (!err.isOperational && process.env.NODE_ENV === 'production') {
    statusCode = 500
    message = '服务器内部错误'
  }

  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  })
}

// 404 处理
export function notFoundHandler(req, res) {
  res.status(404).json({
    success: false,
    message: '请求的资源不存在'
  })
}
