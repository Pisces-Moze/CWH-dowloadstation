<template>
  <div class="home-container">
    <n-layout>
      <n-layout-header class="header">
        <div class="header-content">
          <h1>🐧 智享云阁 CWH</h1>
          <n-space>
            <n-button v-if="!userStore.isLoggedIn" @click="router.push('/login')">登录</n-button>
            <n-button v-if="!userStore.isLoggedIn" @click="router.push('/signup')" type="primary">注册</n-button>
            <n-button v-if="userStore.isLoggedIn" @click="router.push('/upload')" type="primary">上传文件</n-button>
            <n-button v-if="userStore.isLoggedIn" @click="router.push('/control')">控制面板</n-button>
            <n-button v-if="userStore.isLoggedIn" @click="handleLogout" type="error">退出</n-button>
          </n-space>
        </div>
      </n-layout-header>

      <n-layout-content class="content">
        <div class="welcome-section">
          <h2>欢迎来到智享云阁</h2>
          <p>一个免费的公益文件分享平台</p>
        </div>

        <n-card title="📁 文件列表" class="file-list-card">
          <n-space vertical>
            <n-input v-model:value="searchQuery" placeholder="搜索文件..." clearable>
              <template #prefix>
                <n-icon><SearchOutline /></n-icon>
              </template>
            </n-input>

            <n-data-table
              :columns="columns"
              :data="filteredFiles"
              :loading="loading"
              :pagination="pagination"
            />
          </n-space>
        </n-card>
      </n-layout-content>

      <n-layout-footer class="footer">
        <p>© 2026 智享云阁 CWH - 公益下载站</p>
      </n-layout-footer>
    </n-layout>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, h } from 'vue'
import { useRouter } from 'vue-router'
import { useUserStore } from '../stores/user'
import { NLayout, NLayoutHeader, NLayoutContent, NLayoutFooter, NCard, NButton, NSpace, NDataTable, NInput, NIcon, useMessage } from 'naive-ui'
import { SearchOutline } from '@vicons/ionicons5'
import api from '../api/request'

const router = useRouter()
const userStore = useUserStore()
const message = useMessage()

const searchQuery = ref('')
const files = ref([])
const loading = ref(false)

const pagination = {
  pageSize: 10
}

const columns = [
  { title: '文件名', key: 'name' },
  { title: '大小', key: 'size' },
  { title: '上传时间', key: 'uploadTime' },
  {
    title: '操作',
    key: 'actions',
    render: (row) => h(
      NButton,
      {
        size: 'small',
        onClick: () => downloadFile(row)
      },
      { default: () => '下载' }
    )
  }
]

const filteredFiles = computed(() => {
  if (!searchQuery.value) return files.value
  return files.value.filter(file => 
    file.name.toLowerCase().includes(searchQuery.value.toLowerCase())
  )
})

async function loadFiles() {
  loading.value = true
  try {
    const response = await api.get('/files')
    files.value = response.files || []
  } catch (error) {
    message.error('加载文件列表失败')
  } finally {
    loading.value = false
  }
}

function downloadFile(file) {
  window.open(`/api/download/${file.name}`, '_blank')
}

function handleLogout() {
  userStore.logout()
  message.success('已退出登录')
  router.push('/')
}

onMounted(() => {
  loadFiles()
})
</script>

<style scoped>
.home-container {
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.header {
  background: rgba(255, 255, 255, 0.95);
  padding: 1rem 2rem;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.header-content {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header h1 {
  margin: 0;
  color: #667eea;
}

.content {
  max-width: 1200px;
  margin: 2rem auto;
  padding: 0 2rem;
}

.welcome-section {
  text-align: center;
  color: white;
  margin-bottom: 2rem;
}

.welcome-section h2 {
  font-size: 2.5rem;
  margin-bottom: 0.5rem;
}

.file-list-card {
  background: rgba(255, 255, 255, 0.95);
}

.footer {
  background: rgba(0, 0, 0, 0.8);
  color: white;
  text-align: center;
  padding: 1rem;
}
</style>
