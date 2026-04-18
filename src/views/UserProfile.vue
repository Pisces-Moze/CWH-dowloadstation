<template>
  <div class="user-profile-container">
    <n-spin :show="loading">
      <n-space vertical size="large">
        <n-card v-if="userProfile">
          <n-space vertical align="center">
            <n-avatar
              :size="120"
              :src="userProfile.avatarUrl"
            />
            <h2>{{ userProfile.username }}</h2>
            <n-tag :type="userProfile.role === '管理员' ? 'error' : 'info'">
              {{ userProfile.role }}
            </n-tag>
            <n-text v-if="userProfile.bio" depth="3">
              {{ userProfile.bio }}
            </n-text>
          </n-space>

          <n-divider />

          <n-descriptions :column="2" bordered>
            <n-descriptions-item label="公开文件">
              {{ userProfile.publicFileCount }} 个
            </n-descriptions-item>
            <n-descriptions-item label="总下载量">
              {{ userProfile.totalDownloads }} 次
            </n-descriptions-item>
            <n-descriptions-item label="注册时间" :span="2">
              {{ formatDate(userProfile.createdAt) }}
            </n-descriptions-item>
          </n-descriptions>
        </n-card>

        <n-empty v-else description="用户不存在" />
      </n-space>
    </n-spin>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import {
  NCard, NSpace, NAvatar, NTag, NText, NDivider, NDescriptions,
  NDescriptionsItem, NSpin, NEmpty, useMessage
} from 'naive-ui'
import api from '../api/request'

const route = useRoute()
const message = useMessage()

const loading = ref(false)
const userProfile = ref(null)

function formatDate(dateString) {
  if (!dateString) return '-'
  const date = new Date(dateString)
  return date.toLocaleDateString('zh-CN')
}

async function loadUserProfile() {
  loading.value = true
  try {
    const userId = route.params.userId
    const response = await api.get(`/profile/${userId}`)
    userProfile.value = response.user
  } catch (error) {
    message.error('加载用户资料失败')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadUserProfile()
})
</script>

<style scoped>
.user-profile-container {
  max-width: 800px;
  margin: 0 auto;
}
</style>
