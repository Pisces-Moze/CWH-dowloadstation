import { Server } from 'socket.io'

let io = null
const onlineUsers = new Map() // userId -> { socketId, lastSeen }

export function initializeSocket(server) {
  io = new Server(server, {
    cors: {
      origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
      credentials: true
    }
  })

  io.on('connection', (socket) => {
    console.log('用户连接:', socket.id)

    // 用户上线
    socket.on('user:online', (userId) => {
      onlineUsers.set(userId, {
        socketId: socket.id,
        lastSeen: Date.now()
      })
      
      // 广播用户状态变化
      io.emit('user:status', {
        userId,
        status: 'online'
      })
      
      console.log(`用户 ${userId} 上线`)
    })

    // 用户心跳
    socket.on('user:heartbeat', (userId) => {
      if (onlineUsers.has(userId)) {
        onlineUsers.set(userId, {
          socketId: socket.id,
          lastSeen: Date.now()
        })
      }
    })

    // 用户断开连接
    socket.on('disconnect', () => {
      // 找到断开的用户
      for (const [userId, data] of onlineUsers.entries()) {
        if (data.socketId === socket.id) {
          onlineUsers.set(userId, {
            socketId: null,
            lastSeen: Date.now()
          })
          
          // 广播用户离线
          io.emit('user:status', {
            userId,
            status: 'away'
          })
          
          console.log(`用户 ${userId} 离线`)
          break
        }
      }
    })
  })

  // 定期清理长期离线用户
  setInterval(() => {
    const now = Date.now()
    const AWAY_THRESHOLD = 5 * 60 * 1000 // 5分钟
    const OFFLINE_THRESHOLD = 30 * 60 * 1000 // 30分钟

    for (const [userId, data] of onlineUsers.entries()) {
      const timeSinceLastSeen = now - data.lastSeen

      if (timeSinceLastSeen > OFFLINE_THRESHOLD) {
        // 长期离线，从在线列表移除
        onlineUsers.delete(userId)
        io.emit('user:status', {
          userId,
          status: 'offline'
        })
      } else if (timeSinceLastSeen > AWAY_THRESHOLD && data.socketId === null) {
        // 刚离线不久
        io.emit('user:status', {
          userId,
          status: 'away'
        })
      }
    }
  }, 60 * 1000) // 每分钟检查一次

  return io
}

// 获取用户在线状态
export function getUserStatus(userId) {
  if (!onlineUsers.has(userId)) {
    return 'offline'
  }

  const data = onlineUsers.get(userId)
  const now = Date.now()
  const timeSinceLastSeen = now - data.lastSeen

  if (data.socketId && timeSinceLastSeen < 5 * 60 * 1000) {
    return 'online' // 在线
  } else if (timeSinceLastSeen < 30 * 60 * 1000) {
    return 'away' // 刚离线不久
  } else {
    return 'offline' // 长期离线
  }
}

// 获取所有在线用户
export function getOnlineUsers() {
  const users = {}
  for (const [userId, data] of onlineUsers.entries()) {
    users[userId] = getUserStatus(userId)
  }
  return users
}

export { io }
