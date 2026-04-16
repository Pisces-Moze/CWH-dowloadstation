import jwt from 'jsonwebtoken'

export function authMiddleware(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies.token

    if (!token) {
      return res.status(401).json({ message: '未授权，请先登录' })
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = decoded
    next()
  } catch (error) {
    return res.status(401).json({ message: '无效的令牌' })
  }
}
