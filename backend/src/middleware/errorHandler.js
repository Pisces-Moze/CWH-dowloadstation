export function errorHandler(err, req, res, next) {
  console.error('Error:', err)

  const statusCode = err.statusCode || 500
  const message = err.message || '服务器内部错误'

  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  })
}

export class AppError extends Error {
  constructor(message, statusCode = 500) {
    super(message)
    this.statusCode = statusCode
    this.isOperational = true
    Error.captureStackTrace(this, this.constructor)
  }
}
