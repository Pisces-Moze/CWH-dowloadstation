<template>
  <div class="home-container">
    <n-space vertical size="large">
      <!-- 欢迎横幅 -->
      <n-card class="welcome-banner">
        <n-space vertical align="center">
          <n-icon size="64" color="#667eea">
            <CloudDownloadOutline />
          </n-icon>
          <h1>欢迎来到 CWH 下载站</h1>
          <p>企业级文件管理系统 - 安全、快速、可靠</p>
          <n-space v-if="!userStore.isLoggedIn">
            <n-button type="primary" size="large" @click="router.push('/register')">
              立即注册
            </n-button>
            <n-button size="large" @click="router.push('/login')">
              登录
            </n-button>
          </n-space>
        </n-space>
      </n-card>

      <!-- 搜索和筛选 -->
      <n-card>
        <n-space vertical>
          <n-input
            v-model:value="searchKeyword"
            placeholder="搜索文件..."
            size="large"
            clearable
            @update:value="handleSearch"
          >
            <template #prefix>
              <n-icon><SearchOutline /></n-icon>
            </template>
          </n-input>

          <n-space>
            <n-select
              v-model:value="sortBy"
              :options="sortOptions"
              style="width: 150px"
              @update:value="loadFiles"
            />
            <n-button @click="loadFiles">
              <template #icon>
                <n-icon><RefreshOutline /></n-icon>
              </template>
              刷新
            </n-button>
          </n-space>
        </n-space>
      </n-card>

      <!-- 文件列表 -->
      <n-card title="公共文件">
        <n-spin :show="loading">
          <n-empty v-if="files.length === 0" description="暂无文件" />
          <n-list v-else hoverable clickable>
            <n-list-item v-for="file in files" :key="file.id">
              <template #prefix>
                <n-icon size="32" :color="getFileIconColor(file.mimeType)">
                  <component :is="getFileIcon(file.mimeType)" />
                </n-icon>
              </template>

              <n-thing :title="file.name">
                <template #description>
                  <n-space>
                    <n-tag size="small" type="info">{{ file.size }}</n-tag>
                    <n-tag size="small" type="success">
                      <template #icon>
                        <n-icon><DownloadOutline /></n-icon>
                      </template>
                      {{ file.downloads }} 次下载
                    </n-tag>
                    <n-tag v-if="file.downloadRank" size="small" type="warning">
                      排名 #{{ file.downloadRank }}
                    </n-tag>
                    <n-button
                      text
                      type="primary"
                      size="small"
                      @click="router.push(`/profile/${file.userId}`)"
                    >
                      @{{ file.uploader }}
                    </n-button>
                  </n-space>
                </template>
              </n-thing>

              <template #suffix>
                <n-space>
                  <n-button
                    secondary
                    @click="showFileInfo(file)"
                  >
                    详情
                  </n-button>
                  <n-button
                    type="primary"
                    @click="downloadFile(file)"
                  >
                    <template #icon>
                      <n-icon><DownloadOutline /></n-icon>
                    </template>
                    下载
                  </n-button>
                </n-space>
              </template>
            </n-list-item>
          </n-list>

          <!-- 分页 -->
          <n-pagination
            v-if="totalPages > 1"
            v-model:page="currentPage"
            :page-count="totalPages"
            style="margin-top: 20px; justify-content: center"
            @update:page="loadFiles"
          />
        </n-spin>
      </n-card>
    </n-space>

    <!-- 文件详情弹窗 -->
    <FileInfoModal
      v-model:show="showFileInfoModal"
      :file="selectedFile"
    />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import {
  NCard, NSpace, NIcon, NButton, NInput, NSelect, NSpin, NEmpty,
  NList, NListItem, NThing, NTag, NPagination, useMessage
} from 'naive-ui'
import {
  CloudDownloadOutline, SearchOutline, RefreshOutline,
  DownloadOutline, DocumentOutline, ImageOutline,
  VideocamOutline, MusicalNotesOutline, ArchiveOutline
} from '@vicons/ionicons5'
import { useUserStore } from '../stores/user'
import FileInfoModal from '../components/FileInfoModal.vue'
import api from '../api/request'

const router = useRouter()
const message = useMessage()
const userStore = useUserStore()

const loading = ref(false)
const files = ref([])
const searchKeyword = ref('')
const sortBy = ref('downloads')
const currentPage = ref(1)
const totalPages = ref(1)
const pageSize = 20

const showFileInfoModal = ref(false)
const selectedFile = ref(null)

const sortOptions = [
  { label: '下载量', value: 'downloads' },
  { label: '最新上传', value: 'newest' },
  { label: '文件大小', value: 'size' }
]

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

async function loadFiles() {
  loading.value = true
  try {
    const response = await api.get('/files', {
      params: {
        page: currentPage.value,
        pageSize,
        sortBy: sortBy.value,
        search: searchKeyword.value
      }
    })
    files.value = response.files || []
    totalPages.value = response.totalPages || 1
  } catch (error) {
    message.error('加载文件列表失败')
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  currentPage.value = 1
  loadFiles()
}

function showFileInfo(file) {
  selectedFile.value = file
  showFileInfoModal.value = true
}

async function downloadFile(file) {
  try {
    window.open(`/api/files/download/${file.filename}`, '_blank')
    message.success('开始下载')
  } catch (error) {
    message.error('下载失败')
  }
}

onMounted(() => {
  loadFiles()
})
</script>

<style scoped>
.home-container {
  max-width: 1200px;
  margin: 0 auto;
}

.welcome-banner {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  text-align: center;
}

.welcome-banner h1 {
  font-size: 32px;
  margin: 16px 0;
}

.welcome-banner p {
  font-size: 16px;
  opacity: 0.9;
  margin-bottom: 24px;
}
</style>
