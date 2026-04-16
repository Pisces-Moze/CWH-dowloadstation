import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useUserStore = defineStore('user', () => {
  const token = ref(localStorage.getItem('token') || '')
  const username = ref(localStorage.getItem('username') || '')
  const isLoggedIn = ref(!!token.value)

  function setUser(userToken, userName) {
    token.value = userToken
    username.value = userName
    isLoggedIn.value = true
    localStorage.setItem('token', userToken)
    localStorage.setItem('username', userName)
  }

  function logout() {
    token.value = ''
    username.value = ''
    isLoggedIn.value = false
    localStorage.removeItem('token')
    localStorage.removeItem('username')
  }

  return {
    token,
    username,
    isLoggedIn,
    setUser,
    logout
  }
})
