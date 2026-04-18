<template>
  <div class="profile-container">
    <n-space vertical size="large">
      <!-- 个人信息卡片 -->
      <n-card title="个人资料">
        <n-space vertical size="large">
          <!-- 头像 -->
          <n-space align="center">
            <n-avatar
              :size="100"
              :src="userStore.avatarUrl"
              :fallback-src="defaultAvatar"
            />
            <n-upload
              :action="uploadAvatarUrl"
              :headers="uploadHeaders"
              :show-file-list="false"
              accept="image/*"
              @before-upload="handleBeforeUploadAvatar"
              @finish="handleAvatarUploadFinish"
            >
              <n-button>
                <template #icon>
                  <n-icon><CameraOutline /></n-icon>
                </template>
                更换头像
              </n-button>
            </n-upload>
          </n-space>

          <!-- 基本信息 -->
          <n-descriptions :column="2" bordered>
            <n-descriptions-item label="用户名">
              {{ userStore.username }}
            </n-descriptions-item>
            <n-descriptions-item label="邮箱">
              {{ userStore.email }}
            </n-descriptions-item>
            <n-descriptions-item label="角色">
              <n-tag :type="userStore.isAdmin ? 'error' : 'info'">
                {{ userStore.user?.role?.displayName || '普通用户' }}
              </n-tag>
            </n-descriptions-item>
            <n-descriptions-item label="注册时间">
              {{ formatDate(userStore.user?.createdAt) }}
            </n-descriptions-item>
            <n-descriptions-item label="存储使用" :span="2">
              <n-progress
                type="line"
                :percentage="userStore.storagePercent"
                :status="storageStatus"
              >
                {{ formatBytes(userStore.storageUsed) }} / {{ formatBytes(userStore.storageQuota) }}
              </n-progress>
            </n-descriptions-item>
          </n-descriptions>
        </n-space>
      </n-card>

      <!-- 编辑资料 -->
      <n-card title="编辑资料">
        <n-form
          ref="profileFormRef"
          :model="profileForm"
          :rules="profileRules"
          label-placement="left"
          label-width="100"
        >
          <n-form-item path="username" label="用户名">
            <n-input
              v-model:value="profileForm.username"
              placeholder="请输入用户名"
            />
          </n-form-item>

          <n-form-item path="bio" label="个人简介">
            <n-input
              v-model:value="profileForm.bio"
              type="textarea"
              placeholder="介绍一下自己吧"
              :rows="3"
              maxlength="200"
              show-count
            />
          </n-form-item>

          <n-form-item>
            <n-space>
              <n-button
                type="primary"
                :loading="profileLoading"
                @click="handleUpdateProfile"
              >
                保存修改
              </n-button>
              <n-button @click="resetProfileForm">
                重置
              </n-button>
            </n-space>
          </n-form-item>
        </n-form>
      </n-card>

      <!-- 修改密码 -->
      <n-card title="修改密码">
        <n-form
          ref="passwordFormRef"
          :model="passwordForm"
          :rules="passwordRules"
          label-placement="left"
          label-width="100"
        >
          <n-form-item path="oldPassword" label="当前密码">
            <n-input
              v-model:value="passwordForm.oldPassword"
              type="password"
              show-password-on="click"
              placeholder="请输入当前密码"
            />
          </n-form-item>

          <n-form-item path="newPassword" label="新密码">
            <n-input
              v-model:value="passwordForm.newPassword"
              type="password"
              show-password-on="click"
              placeholder="请输入新密码（至少 6 位）"
            />
          </n-form-item>

          <n-form-item path="confirmPassword" label="确认新密码">
            <n-input
              v-model:value="passwordForm.confirmPassword"
              type="password"
              show-password-on="click"
              placeholder="请再次输入新密码"
            />
          </n-form-item>

          <n-form-item>
            <n-button
              type="primary"
              :loading="passwordLoading"
              @click="handleUpdatePassword"
            >
              修改密码
            </n-button>
          </n-form-item>
        </n-form>
      </n-card>
    </n-space>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import {
  NCard, NSpace, NAvatar, NUpload, NButton, NIcon, NDescriptions,
  NDescriptionsItem, NTag, NProgress, NForm, NFormItem, NInput, useMessage
} from 'naive-ui'
import { CameraOutline } from '@vicons/ionicons5'
import { useUserStore } from '../stores/user'

const message = useMessage()
const userStore = useUserStore()

const profileFormRef = ref(null)
const passwordFormRef = ref(null)
const profileLoading = ref(false)
const passwordLoading = ref(false)

const defaultAvatar = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgZmlsbD0iI2RkZCIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBmb250LXNpemU9IjQwIiBmaWxsPSIjOTk5IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBkeT0iLjNlbSI+P jwvdGV4dD48L3N2Zz4='

const profileForm = ref({
  username: '',
  bio: ''
})

const passwordForm = ref({
  oldPassword: '',
  newPassword: '',
  confirmPassword: ''
})

const profileRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 2, max: 20, message: '用户名长度 2-20 位', trigger: 'blur' }
  ]
}

const passwordRules = {
  oldPassword: [
    { required: true, message: '请输入当前密码', trigger: 'blur' }
  ],
  newPassword: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 6, message: '密码至少 6 位', trigger: 'blur' }
  ],
  confirmPassword: [
    { required: true, message: '请再次输入新密码', trigger: 'blur' },
    {
      validator: (rule, value) => {
        return value === passwordForm.value.newPassword
      },
      message: '两次输入的密码不一致',
      trigger: 'blur'
    }
  ]
}

const uploadAvatarUrl = '/api/profile/me/avatar'

const uploadHeaders = computed(() => {
  const token = localStorage.getItem('token')
  return {
    Authorization: `Bearer ${token}`
  }
})

const storageStatus = computed(() => {
  const percent = userStore.storagePercent
  if (percent >= 90) return 'error'
  if (percent >= 70) return 'warning'
  return 'success'
})

function formatBytes(bytes) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

function formatDate(dateString) {
  if (!dateString) return '-'
  const date = new Date(dateString)
  return date.toLocaleString('zh-CN')
}

function resetProfileForm() {
  profileForm.value.username = userStore.username
  profileForm.value.bio = userStore.bio
}

async function handleUpdateProfile() {
  try {
    await profileFormRef.value?.validate()
    profileLoading.value = true

    const result = await userStore.updateProfile(profileForm.value)
    
    if (result.success) {
      message.success('资料更新成功')
    } else {
      message.error(result.message)
    }
  } catch (error) {
    console.error('表单验证失败:', error)
  } finally {
    profileLoading.value = false
  }
}

async function handleUpdatePassword() {
  try {
    await passwordFormRef.value?.validate()
    passwordLoading.value = true

    const result = await userStore.updatePassword(
      passwordForm.value.oldPassword,
      passwordForm.value.newPassword
    )
    
    if (result.success) {
      message.success('密码修改成功')
      passwordForm.value = {
        oldPassword: '',
        newPassword: '',
        confirmPassword: ''
      }
    } else {
      message.error(result.message)
    }
  } catch (error) {
    console.error('表单验证失败:', error)
  } finally {
    passwordLoading.value = false
  }
}

function handleBeforeUploadAvatar(data) {
  const { file } = data
  const maxSize = 5 * 1024 * 1024 // 5MB

  if (!file.type.startsWith('image/')) {
    message.error('只能上传图片文件')
    return false
  }

  if (file.size > maxSize) {
    message.error('图片大小不能超过 5MB')
    return false
  }

  return true
}

async function handleAvatarUploadFinish({ event }) {
  try {
    const response = JSON.parse(event.target.response)
    if (response.success) {
      message.success('头像上传成功')
      await userStore.fetchProfile()
    } else {
      message.error(response.message || '头像上传失败')
    }
  } catch (error) {
    message.error('头像上传失败')
  }
}

onMounted(() => {
  resetProfileForm()
})
</script>

<style scoped>
.profile-container {
  max-width: 800px;
  margin: 0 auto;
}
</style>
