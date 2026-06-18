<template>
  <div class="register-container">
    <n-card class="register-card" title="注册">
      <n-form
        ref="formRef"
        :model="formData"
        :rules="rules"
        size="large"
      >
        <n-form-item path="username" label="用户名">
          <n-input
            v-model:value="formData.username"
            placeholder="请输入用户名"
          >
            <template #prefix>
              <n-icon><PersonOutline /></n-icon>
            </template>
          </n-input>
        </n-form-item>

        <n-form-item path="email" label="邮箱">
          <n-input
            v-model:value="formData.email"
            placeholder="请输入邮箱"
          >
            <template #prefix>
              <n-icon><MailOutline /></n-icon>
            </template>
          </n-input>
        </n-form-item>

        <n-form-item path="code" label="验证码">
          <n-input-group>
            <n-input
              v-model:value="formData.code"
              placeholder="请输入邮箱验证码"
              maxlength="6"
              style="flex: 1"
            >
              <template #prefix>
                <n-icon><ShieldCheckmarkOutline /></n-icon>
              </template>
            </n-input>
            <n-button
              :disabled="countdown > 0 || !formData.email"
              :loading="sendingCode"
              @click="handleSendCode"
            >
              {{ countdown > 0 ? `${countdown}s` : '发送验证码' }}
            </n-button>
          </n-input-group>
        </n-form-item>

        <n-form-item path="password" label="密码">
          <n-input
            v-model:value="formData.password"
            type="password"
            show-password-on="click"
            placeholder="请输入密码（至少 6 位）"
          >
            <template #prefix>
              <n-icon><LockClosedOutline /></n-icon>
            </template>
          </n-input>
        </n-form-item>

        <n-form-item path="confirmPassword" label="确认密码">
          <n-input
            v-model:value="formData.confirmPassword"
            type="password"
            show-password-on="click"
            placeholder="请再次输入密码"
            @keyup.enter="handleRegister"
          >
            <template #prefix>
              <n-icon><LockClosedOutline /></n-icon>
            </template>
          </n-input>
        </n-form-item>

        <n-space vertical size="large">
          <n-button
            type="primary"
            block
            size="large"
            :loading="loading"
            @click="handleRegister"
          >
            注册
          </n-button>

          <div class="login-link">
            已有账号？
            <n-button text type="primary" @click="router.push('/login')">
              立即登录
            </n-button>
          </div>
        </n-space>
      </n-form>
    </n-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { NCard, NForm, NFormItem, NInput, NInputGroup, NButton, NSpace, NIcon, useMessage } from 'naive-ui'
import { PersonOutline, MailOutline, LockClosedOutline, ShieldCheckmarkOutline } from '@vicons/ionicons5'
import { useUserStore } from '../stores/user'
import api from '../api/request'

const router = useRouter()
const message = useMessage()
const userStore = useUserStore()

const formRef = ref(null)
const loading = ref(false)
const sendingCode = ref(false)
const countdown = ref(0)

const formData = ref({
  username: '',
  email: '',
  code: '',
  password: '',
  confirmPassword: ''
})

const rules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 2, max: 20, message: '用户名长度 2-20 位', trigger: 'blur' }
  ],
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '请输入有效的邮箱地址', trigger: 'blur' }
  ],
  code: [
    { required: true, message: '请输入验证码', trigger: 'blur' },
    { len: 6, message: '验证码为 6 位数字', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码至少 6 位', trigger: 'blur' }
  ],
  confirmPassword: [
    { required: true, message: '请再次输入密码', trigger: 'blur' },
    {
      validator: (rule, value) => {
        return value === formData.value.password
      },
      message: '两次输入的密码不一致',
      trigger: 'blur'
    }
  ]
}

async function handleSendCode() {
  // 验证邮箱
  if (!formData.value.email) {
    message.error('请先输入邮箱')
    return
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(formData.value.email)) {
    message.error('请输入有效的邮箱地址')
    return
  }

  sendingCode.value = true
  try {
    await api.post('/auth/send-code', { email: formData.value.email })
    message.success('验证码已发送到您的邮箱')
    
    // 开始倒计时
    countdown.value = 60
    const timer = setInterval(() => {
      countdown.value--
      if (countdown.value <= 0) {
        clearInterval(timer)
      }
    }, 1000)
  } catch (error) {
    message.error(error.response?.data?.message || '验证码发送失败')
  } finally {
    sendingCode.value = false
  }
}

async function handleRegister() {
  try {
    await formRef.value?.validate()
    loading.value = true

    const result = await userStore.register(
      formData.value.username,
      formData.value.email,
      formData.value.password,
      formData.value.code
    )
    
    if (result.success) {
      message.success('注册成功')
      router.push('/')
    } else {
      message.error(result.message)
    }
  } catch (error) {
    console.error('表单验证失败:', error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.register-container {
  min-height: calc(100vh - 200px);
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 20px;
}

.register-card {
  width: 100%;
  max-width: 400px;
}

.login-link {
  text-align: center;
  color: #666;
}
</style>
