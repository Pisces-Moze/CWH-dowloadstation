<template>
  <div class="control-container">
    <n-card class="control-card" title="🎛️ 控制面板">
      <n-space vertical size="large">
        <n-alert type="info">
          欢迎，{{ userStore.username }}！
        </n-alert>

        <n-tabs type="line" animated>
          <n-tab-pane name="files" tab="我的文件">
            <n-space vertical>
              <n-data-table
                :columns="fileColumns"
                :data="myFiles"
                :loading="loading"
                :pagination="pagination"
              />
            </n-space>
          </n-tab-pane>

          <n-tab-pane name="stats" tab="统计信息">
            <n-space vertical>
              <n-statistic label="上传文件数" :value="stats.totalFiles" />
              <n-statistic label="总大小" :value="stats.totalSize" />
              <n-statistic label="下载次数" :value="stats.downloads" />
            </n-space>
          </n-tab-pane>
        </n-tabs>

        <n-space>
          <n-button @click="router.push('/')">返回首页</n-button>
          <n-button @click="router.push('/upload')" type="primary">上传文件</n-button>
        </n-space>
      </n-space>
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted, h } from 'vue'
import { useRouter } from 'vue-router'
import { useUserStore } from '../stores/user'
import { NCard, NSpace, NAlert, NTabs, NTabPane, NDataTable, NStatistic, NButton, NPopconfirm, useMessage } from 'naive-ui'
import api from '../api/request'

const router = useRouter()
const userStore = useUserStore()
const message = useMessage()

const loading = ref(false)
const myFiles = ref([])
const stats = ref({
  totalFiles: 0,
  totalSize: '0 MB',
  downloads: 0
})

const pagination = {
  pageSize: 10
}

const fileColumns = [
  { title: '文件名', key: 'name' },
  { title: '大小', key: 'size' },
  { title: '上传时间', key: 'uploadTime' },
  { title: '下载次数', key: 'downloads' },
  {
    title: '操作',
    key: 'actions',
    render: (row) => h(
      NPopconfirm,
      {
        onPositiveClick: () => deleteFile(row)
      },
      {
        default: () => '确定删除这个文件吗？',
        trigger: () => h(NButton, { size: 'small', type: 'error' }, { default: () => '删除' })
      }
    )
  }
]

async function loadMyFiles() {
  loading.value = true
  try {
    const response = await api.get('/my-files')
    myFiles.value = response.files || []
    stats.value = response.stats || stats.value
  } catch (error) {
    message.error('加载文件列表失败')
  } finally {
    loading.value = false
  }
}

async function deleteFile(file) {
  try {
    await api.delete(`/files/${file.id}`)
    message.success('删除成功')
    loadMyFiles()
  } catch (error) {
    message.error('删除失败')
  }
}

onMounted(() => {
  loadMyFiles()
})
</script>

<style scoped>
.control-container {
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 2rem;
}

.control-card {
  width: 900px;
  max-width: 100%;
}
</style>
