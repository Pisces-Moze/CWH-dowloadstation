import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../api/request'

export const useUserStore = defineStore('user', () => {
  // State
  const token = ref(localStorage.getItem('token') || '')
  const user = ref(null)
  const isLoading = ref(false)

  // Getters
  const isLoggedIn = computed(() => !!token.value)
  const isAdmin = computed(() => user.value?.role?.name === 'admin')
  const username = computed(() => user.value?.username || '')
  const email = computed(() => user.value?.email || '')
  const avatarUrl = computed(() => user.value?.avatarUrl || '')
  const bio = computed(() => user.value?.bio || '')
  const storageUsed = computed(() => user.value?.storageUsed || 0)
  const storageQuota = computed(() => user.value?.storageQuota || 0)
  const storagePercent = computed(() => {
    if (!storageQuota.value) return 0
    return Math.round((storageUsed.value / storageQuota.value) * 100)
  })

  // Actions
  async function login(email, password) {
    try {
      isLoading.value = true
      const response = await api.post('/auth/login', { email, password })
      token.value = response.token
      localStorage.setItem('token', response.token)
      await fetchProfile()
      return { success: true }
    } catch (error) {
      return { success: false, message: error.message || '登录失败' }
    } finally {
      isLoading.value = false
    }
  }

  async function register(username, email, password) {
    try {
      isLoading.value = true
      const response = await api.post('/auth/register', { username, email, password })
      token.value = response.token
      localStorage.setItem('token', response.token)
      await fetchProfile()
      return { success: true }
    } catch (error) {
      return { success: false, message: error.message || '注册失败' }
    } finally {
      isLoading.value = false
    }
  }

  async function fetchProfile() {
    try {
      const response = await api.get('/profile/me')
      user.value = response.user
    } catch (error) {
      console.error('获取用户信息失败:', error)
    }
  }

  async function updateProfile(data) {
    try {
      await api.put('/profile/me', data)
      await fetchProfile()
      return { success: true }
    } catch (error) {
      return { success: false, message: error.message || '更新失败' }
    }
  }

  async function updatePassword(oldPassword, newPassword) {
    try {
      await api.put('/profile/me/password', { oldPassword, newPassword })
      return { success: true }
    } catch (error) {
      return { success: false, message: error.message || '修改密码失败' }
    }
  }

  async function uploadAvatar(file) {
    try {
      const formData = new FormData()
      formData.append('avatar', file)
      const response = await api.post('/profile/me/avatar', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      await fetchProfile()
      return { success: true, avatarUrl: response.avatarUrl }
    } catch (error) {
      return { success: false, message: error.message || '上传头像失败' }
    }
  }

  function logout() {
    token.value = ''
    user.value = null
    localStorage.removeItem('token')
  }

  return {
    // State
    token,
    user,
    isLoading,
    // Getters
    isLoggedIn,
    isAdmin,
    username,
    email,
    avatarUrl,
    bio,
    storageUsed,
    storageQuota,
    storagePercent,
    // Actions
    login,
    register,
    fetchProfile,
    updateProfile,
    updatePassword,
    uploadAvatar,
    logout
  }
})
