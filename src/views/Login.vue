<template>
  <div class="login-container">
    <n-card class="login-card" title="登录">
      <n-form ref="formRef" :model="formData" :rules="rules">
        <n-form-item label="用户名" path="username">
          <n-input v-model:value="formData.username" placeholder="请输入用户名" />
        </n-form-item>
        <n-form-item label="密码" path="password">
          <n-input v-model:value="formData.password" type="password" placeholder="请输入密码" show-password-on="click" />
        </n-form-item>
        <n-space vertical>
          <n-button type="primary" block @click="handleLogin" :loading="loading">登录</n-button>
          <n-button text @click="router.push('/signup')">还没有账号？去注册</n-button>
          <n-button text @click="router.push('/')">返回首页</n-button>
        </n-space>
      </n-form>
    </n-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useUserStore } from '../stores/user'
import { NCard, NForm, NFormItem, NInput, NButton, NSpace, useMessage } from 'naive-ui'
import api from '../api/request'

const router = useRouter()
const userStore = useUserStore()
const message = useMessage()

const formRef = ref(null)
const loading = ref(false)
const formData = ref({
  username: '',
  password: ''
})

const rules = {
  username: { required: true, message: '请输入用户名', trigger: 'blur' },
  password: { required: true, message: '请输入密码', trigger: 'blur' }
}

async function handleLogin() {
  try {
    await formRef.value?.validate()
    loading.value = true
    
    const response = await api.post('/login', formData.value)
    
    if (response.token) {
      userStore.setUser(response.token, formData.value.username)
      message.success('登录成功')
      router.push('/')
    } else {
      message.error(response.message || '登录失败')
    }
  } catch (error) {
    if (error.response) {
      message.error(error.response.data?.message || '登录失败')
    }
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-container {
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.login-card {
  width: 400px;
  max-width: 90%;
}
</style>
