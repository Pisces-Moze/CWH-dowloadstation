<template>
  <div class="share-container">
    <n-card class="share-card">
      <n-spin :show="loading">
        <n-space vertical size="large" align="center">
          <n-icon size="64" color="#667eea">
            <ShareSocialOutline />
          </n-icon>

          <h2>文件分享</h2>

          <!-- 需要密码 -->
          <n-form
            v-if="needPassword && !verified"
            ref="formRef"
            :model="formData"
            style="width: 100%; max-width: 400px"
          >
            <n-form-item label="访问密码">
              <n-input
                v-model:value="formData.password"
                type="password"
                placeholder="请输入访问密码"
                @keyup.enter="handleVerify"
              />
            </n-form-item>
            <n-button
              type="primary"
              block
              :loading="verifying"
              @click="handleVerify"
            >
              验证
            </n-button>
          </n-form>

          <!-- 文件信息 -->
          <n-descriptions v-if="fileInfo && verified" :column="1" bordered style="width: 100%">
            <n-descriptions-item label="文件名">
              {{ fileInfo.name }}
            </n-descriptions-item>
            <n-descriptions-item label="文件大小">
              {{ fileInfo.size }}
            </n-descriptions-item>
            <n-descriptions-item label="分享者">
              {{ fileInfo.uploader }}
            </n-descriptions-item>
            <n-descriptions-item v-if="fileInfo.expiresAt" label="过期时间">
              {{ formatDate(fileInfo.expiresAt) }}
            </n-descriptions-item>
            <n-descriptions-item v-if="fileInfo.maxDownloads" label="剩余下载次数">
              {{ fileInfo.remainingDownloads }} / {{ fileInfo.maxDownloads }}
            </n-descriptions-item>
          </n-descriptions>

          <n-button
            v-if="fileInfo && verified"
            type="primary"
            size="large"
            @click="handleDownload"
          >
            <template #icon>
              <n-icon><DownloadOutline /></n-icon>
            </template>
            下载文件
          </n-button>

          <n-alert v-if="error" type="error">
            {{ error }}
          </n-alert>
        </n-space>
      </n-spin>
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import {
  NCard, NSpin, NSpace, NIcon, NForm, NFormItem, NInput, NButton,
  NDescriptions, NDescriptionsItem, NAlert, useMessage
} from 'naive-ui'
import { ShareSocialOutline, DownloadOutline } from '@vicons/ionicons5'
import api from '../api/request'

const route = useRoute()
const message = useMessage()

const loading = ref(false)
const verifying = ref(false)
const needPassword = ref(false)
const verified = ref(false)
const fileInfo = ref(null)
const error = ref('')

const formRef = ref(null)
const formData = ref({
  password: ''
})

function formatDate(dateString) {
  if (!dateString) return '-'
  const date = new Date(dateString)
  return date.toLocaleString('zh-CN')
}

async function loadShareInfo() {
  loading.value = true
  error.value = ''
  try {
    const shareCode = route.params.code
    const response = await api.get(`/files/share/${shareCode}`)
    
    if (response.needPassword) {
      needPassword.value = true
      verified.value = false
    } else {
      fileInfo.value = response.file
      verified.value = true
    }
  } catch (err) {
    error.value = err.response?.data?.message || '分享链接无效或已过期'
  } finally {
    loading.value = false
  }
}

async function handleVerify() {
  verifying.value = true
  error.value = ''
  try {
    const shareCode = route.params.code
    const response = await api.post(`/files/share/${shareCode}/verify`, {
      password: formData.value.password
    })
    
    fileInfo.value = response.file
    verified.value = true
    message.success('验证成功')
  } catch (err) {
    error.value = err.response?.data?.message || '密码错误'
  } finally {
    verifying.value = false
  }
}

function handleDownload() {
  if (fileInfo.value) {
    const shareCode = route.params.code
    window.open(`/api/files/share/${shareCode}/download`, '_blank')
    message.success('开始下载')
  }
}

onMounted(() => {
  loadShareInfo()
})
</script>

<style scoped>
.share-container {
  min-height: calc(100vh - 200px);
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 20px;
}

.share-card {
  width: 100%;
  max-width: 600px;
}
</style>
