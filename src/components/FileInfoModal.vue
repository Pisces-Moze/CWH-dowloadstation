<template>
  <n-modal
    v-model:show="showModal"
    preset="card"
    title="文件详情"
    style="width: 600px"
    :bordered="false"
  >
    <n-spin :show="loading">
      <n-descriptions v-if="fileInfo" :column="1" bordered>
        <n-descriptions-item label="文件名">
          {{ fileInfo.name }}
        </n-descriptions-item>

        <n-descriptions-item label="文件大小">
          {{ formatBytes(fileInfo.size) }}
        </n-descriptions-item>

        <n-descriptions-item label="文件类型">
          {{ fileInfo.mimeType || '未知' }}
        </n-descriptions-item>

        <n-descriptions-item label="MD5 校验值">
          <n-text code>{{ fileInfo.md5 }}</n-text>
        </n-descriptions-item>

        <n-descriptions-item label="下载次数">
          <n-space>
            <n-tag type="success">{{ fileInfo.downloads }} 次</n-tag>
            <n-tag v-if="fileInfo.downloadRank" type="warning">
              排名 #{{ fileInfo.downloadRank }}
            </n-tag>
          </n-space>
        </n-descriptions-item>

        <n-descriptions-item label="上传者">
          <n-button
            text
            type="primary"
            @click="router.push(`/profile/${fileInfo.uploaderUserId}`)"
          >
            {{ fileInfo.uploader }}
          </n-button>
        </n-descriptions-item>

        <n-descriptions-item label="上传时间">
          {{ formatDate(fileInfo.uploadTime) }}
        </n-descriptions-item>

        <n-descriptions-item v-if="fileInfo.isPrivate" label="文件类型">
          <n-tag type="error">私人文件</n-tag>
        </n-descriptions-item>
      </n-descriptions>
    </n-spin>

    <template #footer>
      <n-space justify="end">
        <n-button @click="showModal = false">关闭</n-button>
        <n-button
          v-if="canShare"
          type="primary"
          @click="handleShare"
        >
          创建分享链接
        </n-button>
        <n-button
          type="primary"
          @click="handleDownload"
        >
          <template #icon>
            <n-icon><DownloadOutline /></n-icon>
          </template>
          下载
        </n-button>
      </n-space>
    </template>
  </n-modal>

  <!-- 分享链接弹窗 -->
  <ShareModal
    v-model:show="showShareModal"
    :file-id="props.file?.id"
  />
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import {
  NModal, NSpin, NDescriptions, NDescriptionsItem, NText,
  NTag, NSpace, NButton, NIcon, useMessage
} from 'naive-ui'
import { DownloadOutline } from '@vicons/ionicons5'
import { useUserStore } from '../stores/user'
import ShareModal from './ShareModal.vue'
import api from '../api/request'

const props = defineProps({
  show: Boolean,
  file: Object
})

const emit = defineEmits(['update:show'])

const router = useRouter()
const message = useMessage()
const userStore = useUserStore()

const showModal = computed({
  get: () => props.show,
  set: (val) => emit('update:show', val)
})

const loading = ref(false)
const fileInfo = ref(null)
const showShareModal = ref(false)

const canShare = computed(() => {
  return userStore.isLoggedIn && 
         fileInfo.value && 
         !fileInfo.value.isPrivate &&
         fileInfo.value.uploaderUserId === userStore.user?.id
})

watch(() => props.file, async (newFile) => {
  if (newFile) {
    await loadFileInfo(newFile.id)
  }
})

async function loadFileInfo(fileId) {
  loading.value = true
  try {
    const response = await api.get(`/files/file-info/${fileId}`)
    fileInfo.value = response.file
  } catch (error) {
    message.error('加载文件详情失败')
  } finally {
    loading.value = false
  }
}

function formatDate(dateString) {
  if (!dateString) return '-'
  const date = new Date(dateString)
  return date.toLocaleString('zh-CN')
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

function handleDownload() {
  if (fileInfo.value) {
    window.open(`/api/files/download/${fileInfo.value.filename}`, '_blank')
    message.success('开始下载')
  }
}

function handleShare() {
  showShareModal.value = true
}
</script>
