import { io } from 'socket.io-client'
import { ref } from 'vue'

const socket = io(import.meta.env.VITE_API_BASE_URL?.replace('/api', '') || 'http://localhost:3000', {
  autoConnect: false
})

// 用户在线状态 Map
export const userStatuses = ref(new Map())

// 连接 WebSocket
export function connectSocket(userId) {
  if (!userId) return

  socket.connect()

  socket.on('connect', () => {
    console.log('WebSocket 已连接')
    socket.emit('user:online', userId)

    // 每 30 秒发送心跳
    setInterval(() => {
      socket.emit('user:heartbeat', userId)
    }, 30000)
  })

  socket.on('user:status', ({ userId, status }) => {
    userStatuses.value.set(userId, status)
  })

  socket.on('disconnect', () => {
    console.log('WebSocket 已断开')
  })
}

// 断开 WebSocket
export function disconnectSocket() {
  socket.disconnect()
}

// 获取用户状态
export function getUserStatus(userId) {
  return userStatuses.value.get(userId) || 'offline'
}

// 获取状态颜色
export function getStatusColor(status) {
  switch (status) {
    case 'online':
      return '#18a058' // 蓝绿色（在线）
    case 'away':
      return '#f0a020' // 黄色（离开）
    case 'offline':
    default:
      return '#d03050' // 红色（离线）
  }
}

// 获取状态文本
export function getStatusText(status) {
  switch (status) {
    case 'online':
      return '在线'
    case 'away':
      return '离开'
    case 'offline':
    default:
      return '离线'
  }
}

export default socket
