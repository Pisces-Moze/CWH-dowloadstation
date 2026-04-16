<template>
  <div class="upload-container">
    <n-card class="upload-card" title="📤 上传文件">
      <n-space vertical size="large">
        <n-upload
          :custom-request="handleUpload"
          :max="5"
          multiple
          directory-dnd
        >
          <n-upload-dragger>
            <div style="margin-bottom: 12px">
              <n-icon size="48" :depth="3">
                <CloudUploadOutline />
              </n-icon>
            </div>
            <n-text style="font-size: 16px">
              点击或拖拽文件到此区域上传
            </n-text>
            <n-p depth="3" style="margin: 8px 0 0 0">
              支持单个或批量上传，最多同时上传5个文件
            </n-p>
          </n-upload-dragger>
        </n-upload>

        <n-progress
          v-if="uploading"
          type="line"
          :percentage="uploadProgress"
          :indicator-placement="'inside'"
          processing
        />

        <n-space>
          <n-button @click="router.push('/')">返回首页</n-button>
        </n-space>
      </n-space>
    </n-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { NCard, NUpload, NUploadDragger, NButton, NSpace, NIcon, NText, NP, NProgress, useMessage } from 'naive-ui'
import { CloudUploadOutline } from '@vicons/ionicons5'
import api from '../api/request'

const router = useRouter()
const message = useMessage()

const uploading = ref(false)
const uploadProgress = ref(0)

async function handleUpload({ file, onFinish, onError, onProgress }) {
  const formData = new FormData()
  formData.append('file', file.file)

  uploading.value = true
  uploadProgress.value = 0

  try {
    await api.post('/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      },
      onUploadProgress: (progressEvent) => {
        uploadProgress.value = Math.round((progressEvent.loaded * 100) / progressEvent.total)
        onProgress({ percent: uploadProgress.value })
      }
    })

    message.success(`${file.name} 上传成功`)
    onFinish()
  } catch (error) {
    message.error(`${file.name} 上传失败`)
    onError()
  } finally {
    uploading.value = false
    uploadProgress.value = 0
  }
}
</script>

<style scoped>
.upload-container {
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 2rem;
}

.upload-card {
  width: 600px;
  max-width: 100%;
}
</style>
