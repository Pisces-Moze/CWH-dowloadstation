<template>
  <div class="private-container">
    <n-space vertical size="large">
      <!-- 存储统计 -->
      <n-card>
        <n-space vertical>
          <n-statistic label="存储使用情况">
            <n-progress
              type="line"
              :percentage="userStore.storagePercent"
              :status="storageStatus"
              :height="24"
            >
              {{ formatBytes(userStore.storageUsed) }} / {{ formatBytes(userStore.storageQuota) }}
            </n-progress>
          </n-statistic>

          <n-space>
            <n-button type="primary" @click="showUploadModal = true">
              <template #icon>
                <n-icon><CloudUploadOutline /></n-icon>
              </template>
              上传文件
            </n-button>
            <n-button @click="loadFiles">
              <template #icon>
                <n-icon><RefreshOutline /></n-icon>
              </template>
              刷新
            </n-button>
            <n-button
              v-if="invalidReferences.length > 0"
              type="error"
              @click="cleanInvalidReferences"
            >
              清理失效引用 ({{ invalidReferences.length }})
            </n-button>
          </n-space>
        </n-space>
      </n-card>

      <!-- 文件列表 -->
      <n-card title="我的私人文件">
        <n-spin :show="loading">
          <n-empty v-if="files.length === 0" description="暂无文件，快去上传吧！" />
          <n-list v-else hoverable>
            <n-list-item
              v-for="file in files"
              :key="file.id"
              :class="{ 'invalid-file': file.isInvalid }"
            >
              <template #prefix>
                <n-icon
                  size="32"
                  :color="file.isInvalid ? '#ccc' : getFileIconColor(file.mimeType)"
                >
                  <component :is="getFileIcon(file.mimeType)" />
                </n-icon>
              </template>

              <n-thing>
                <template #header>
                  <span :style="{ textDecoration: file.isInvalid ? 'line-through' : 'none' }">
                    {{ file.name }}
                    <n-tag v-if="file.isInvalid" type="error" size="small">已失效</n-tag>
                    <n-tag v-if="file.isReference" type="info" size="small">引用</n-tag>
                  </span>
                </template>
                <template #description>
                  <n-space>
                    <n-tag size="small" type="info">{{ formatBytes(file.size) }}</n-tag>
                    <n-text depth="3">{{ formatDate(file.uploadTime) }}</n-text>
                  </n-space>
                </template>
              </n-thing>

              <template #suffix>
                <n-space>
                  <n-button
                    v-if="!file.isInvalid"
                    secondary
                    size="small"
                    @click="showFileInfo(file)"
                  >
                    详情
                  </n-button>
                  <n-button
                    v-if="!file.isInvalid"
                    type="primary"
                    size="small"
                    @click="downloadFile(file)"
                  >
                    下载
                  </n-button>
                  <n-popconfirm
                    @positive-click="deleteFile(file)"
                  >
                    <template #trigger>
                      <n-button type="error" size="small">
                        删除
                      </n-button>
                    </template>
                    确定删除这个文件吗？
                  </n-popconfirm>
                </n-space>
              </template>
            </n-list-item>
          </n-list>
        </n-spin>
      </n-card>
    </n-space>

    <!-- 上传文件弹窗 -->
    <UploadModal
      v-model:show="showUploadModal"
      :is-private="true"
      @success="loadFiles"
    />

    <!-- 文件详情弹窗 -->
    <FileInfoModal
      v-model:show="showFileInfoModal"
      :file="selectedFile"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import {
  NCard, NSpace, NStatistic, NProgress, NButton, NIcon, NSpin,
  NEmpty, NList, NListItem, NThing, NTag, NText, NPopconfirm, useMessage, useDialog
} from 'naive-ui'
import {
  CloudUploadOutline, RefreshOutline, DocumentOutline,
  ImageOutline, VideocamOutline, MusicalNotesOutline, ArchiveOutline
} from '@vicons/ionicons5'
import { useUserStore } from '../stores/user'
import UploadModal from '../components/UploadModal.vue'
import FileInfoModal from '../components/FileInfoModal.vue'
import api from '../api/request'

const message = useMessage()
const dialog = useDialog()
const userStore = useUserStore()

const loading = ref(false)
const files = ref([])
const showUploadModal = ref(false)
const showFileInfoModal = ref(false)
const selectedFile = ref(null)

const storageStatus = computed(() => {
  const percent = userStore.storagePercent
  if (percent >= 90) return 'error'
  if (percent >= 70) return 'warning'
  return 'success'
})

const invalidReferences = computed(() => {
  return files.value.filter(f => f.isInvalid)
})

function getFileIcon(mimeType) {
  if (!mimeType) return DocumentOutline
  if (mimeType.startsWith('image/')) return ImageOutline
  if (mimeType.startsWith('video/')) return VideocamOutline
  if (mimeType.startsWith('audio/')) return MusicalNotesOutline
  if (mimeType.includes('zip') || mimeType.includes('rar')) return ArchiveOutline
  return DocumentOutline
}

function getFileIconColor(mimeType) {
  if (!mimeType) return '#666'
  if (mimeType.startsWith('image/')) return '#52c41a'
  if (mimeType.startsWith('video/')) return '#1890ff'
  if (mimeType.startsWith('audio/')) return '#722ed1'
  if (mimeType.includes('zip') || mimeType.includes('rar')) return '#fa8c16'
  return '#666'
}

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

async function loadFiles() {
  loading.value = true
  try {
    const response = await api.get('/private-files')
    files.value = response.files || []
    await userStore.fetchProfile() // 更新存储使用情况
  } catch (error) {
    message.error('加载文件列表失败')
  } finally {
    loading.value = false
  }
}

function showFileInfo(file) {
  selectedFile.value = file
  showFileInfoModal.value = true
}

function downloadFile(file) {
  window.open(`/api/files/download/${file.filename}`, '_blank')
  message.success('开始下载')
}

async function deleteFile(file) {
  try {
    await api.delete(`/files/${file.id}`)
    message.success('删除成功')
    loadFiles()
  } catch (error) {
    message.error('删除失败')
  }
}

async function cleanInvalidReferences() {
  dialog.warning({
    title: '确认清理',
    content: `确定要清理 ${invalidReferences.value.length} 个失效引用吗？`,
    positiveText: '确定',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await api.post('/files/clean-invalid-references')
        message.success('清理成功')
        loadFiles()
      } catch (error) {
        message.error('清理失败')
      }
    }
  })
}

onMounted(() => {
  loadFiles()
})
</script>

<style scoped>
.private-container {
  max-width: 1200px;
  margin: 0 auto;
}

.invalid-file {
  opacity: 0.6;
}
</style>
