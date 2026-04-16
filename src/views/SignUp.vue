<template>
  <div class="signup-container">
    <n-card class="signup-card" title="注册">
      <n-form ref="formRef" :model="formData" :rules="rules">
        <n-form-item label="用户名" path="username">
          <n-input v-model:value="formData.username" placeholder="请输入用户名" />
        </n-form-item>
        <n-form-item label="邮箱" path="email">
          <n-input v-model:value="formData.email" placeholder="请输入邮箱" />
        </n-form-item>
        <n-form-item label="密码" path="password">
          <n-input v-model:value="formData.password" type="password" placeholder="请输入密码" show-password-on="click" />
        </n-form-item>
        <n-form-item label="确认密码" path="confirmPassword">
          <n-input v-model:value="formData.confirmPassword" type="password" placeholder="请再次输入密码" show-password-on="click" />
        </n-form-item>
        <n-space vertical>
          <n-button type="primary" block @click="handleSignUp" :loading="loading">注册</n-button>
          <n-button text @click="router.push('/login')">已有账号？去登录</n-button>
          <n-button text @click="router.push('/')">返回首页</n-button>
        </n-space>
      </n-form>
    </n-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { NCard, NForm, NFormItem, NInput, NButton, NSpace, useMessage } from 'naive-ui'
import api from '../api/request'

const router = useRouter()
const message = useMessage()

const formRef = ref(null)
const loading = ref(false)
const formData = ref({
  username: '',
  email: '',
  password: '',
  confirmPassword: ''
})

const rules = {
  username: { required: true, message: '请输入用户名', trigger: 'blur' },
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '请输入有效的邮箱地址', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码至少6位', trigger: 'blur' }
  ],
  confirmPassword: [
    { required: true, message: '请再次输入密码', trigger: 'blur' },
    {
      validator: (rule, value) => value === formData.value.password,
      message: '两次密码不一致',
      trigger: 'blur'
    }
  ]
}

async function handleSignUp() {
  try {
    await formRef.value?.validate()
    loading.value = true
    
    const response = await api.post('/signup', {
      username: formData.value.username,
      email: formData.value.email,
      password: formData.value.password
    })
    
    message.success('注册成功，请登录')
    router.push('/login')
  } catch (error) {
    message.error(error.response?.data?.message || '注册失败')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.signup-container {
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.signup-card {
  width: 400px;
  max-width: 90%;
}
</style>
