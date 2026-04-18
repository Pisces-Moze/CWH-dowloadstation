<template>
  <div class="admin-container">
    <n-space vertical size="large">
      <!-- 统计卡片 -->
      <n-grid :cols="4" :x-gap="16">
        <n-gi>
          <n-card>
            <n-statistic label="总用户数" :value="stats.totalUsers">
              <template #prefix>
                <n-icon size="24" color="#1890ff">
                  <PeopleOutline />
                </n-icon>
              </template>
            </n-statistic>
          </n-card>
        </n-gi>
        <n-gi>
          <n-card>
            <n-statistic label="总文件数" :value="stats.totalFiles">
              <template #prefix>
                <n-icon size="24" color="#52c41a">
                  <DocumentTextOutline />
                </n-icon>
              </template>
            </n-statistic>
          </n-card>
        </n-gi>
        <n-gi>
          <n-card>
            <n-statistic label="总下载量" :value="stats.totalDownloads">
              <template #prefix>
                <n-icon size="24" color="#722ed1">
                  <DownloadOutline />
                </n-icon>
              </template>
            </n-statistic>
          </n-card>
        </n-gi>
        <n-gi>
          <n-card>
            <n-statistic label="在线人数" :value="stats.onlineUsers">
              <template #prefix>
                <n-icon size="24" color="#fa8c16">
                  <PulseOutline />
                </n-icon>
              </template>
            </n-statistic>
          </n-card>
        </n-gi>
      </n-grid>

      <!-- 标签页 -->
      <n-card>
        <n-tabs type="line" animated>
          <!-- 文件排行榜 -->
          <n-tab-pane name="files" tab="文件下载排行">
            <n-spin :show="loading">
              <n-list bordered>
                <n-list-item v-for="(file, index) in stats.topFiles" :key="file.id">
                  <template #prefix>
                    <n-tag :type="getRankType(index)" round>
                      #{{ index + 1 }}
                    </n-tag>
                  </template>
                  <n-thing :title="file.name">
                    <template #description>
                      <n-space>
                        <n-tag size="small">{{ formatBytes(file.size) }}</n-tag>
                        <n-tag size="small" type="success">
                          {{ file.downloads }} 次下载
                        </n-tag>
                      </n-space>
                    </template>
                  </n-thing>
                </n-list-item>
              </n-list>
            </n-spin>
          </n-tab-pane>

          <!-- 用户排行榜 -->
          <n-tab-pane name="users" tab="用户上传排行">
            <n-spin :show="loading">
              <n-list bordered>
                <n-list-item v-for="(user, index) in stats.topUploaders" :key="user.id">
                  <template #prefix>
                    <n-tag :type="getRankType(index)" round>
                      #{{ index + 1 }}
                    </n-tag>
                  </template>
                  <n-thing>
                    <template #avatar>
                      <UserAvatar
                        :src="user.avatarUrl"
                        :user-id="user.id"
                        :size="40"
                      />
                    </template>
                    <template #header>
                      {{ user.username }}
                    </template>
                    <template #description>
                      <n-space>
                        <n-tag size="small">{{ user.fileCount }} 个文件</n-tag>
                        <n-tag size="small" type="info">
                          {{ user.totalSize }}
                        </n-tag>
                      </n-space>
                    </template>
                  </n-thing>
                  <template #suffix>
                    <n-button
                      text
                      type="primary"
                      @click="router.push(`/profile/${user.id}`)"
                    >
                      查看资料
                    </n-button>
                  </template>
                </n-list-item>
              </n-list>
            </n-spin>
          </n-tab-pane>

          <!-- 下载趋势 -->
          <n-tab-pane name="trend" tab="下载趋势">
            <n-spin :show="loading">
              <div style="height: 300px">
                <n-empty v-if="!stats.downloadTrend || stats.downloadTrend.length === 0" 
                  description="暂无数据" 
                />
                <div v-else>
                  <n-list>
                    <n-list-item v-for="item in stats.downloadTrend" :key="item.date">
                      <n-space align="center" style="width: 100%">
                        <n-text>{{ item.date }}</n-text>
                        <n-progress
                          type="line"
                          :percentage="getTrendPercent(item.count)"
                          :show-indicator="false"
                          style="flex: 1"
                        />
                        <n-text strong>{{ item.count }} 次</n-text>
                      </n-space>
                    </n-list-item>
                  </n-list>
                </div>
              </div>
            </n-spin>
          </n-tab-pane>

          <!-- 用户管理 -->
          <n-tab-pane name="manage" tab="用户管理">
            <n-spin :show="loading">
              <n-space vertical>
                <n-input
                  v-model:value="userSearchKeyword"
                  placeholder="搜索用户..."
                  clearable
                  @update:value="loadUsers"
                >
                  <template #prefix>
                    <n-icon><SearchOutline /></n-icon>
                  </template>
                </n-input>

                <n-data-table
                  :columns="userColumns"
                  :data="users"
                  :pagination="{ pageSize: 10 }"
                />
              </n-space>
            </n-spin>
          </n-tab-pane>
        </n-tabs>
      </n-card>
    </n-space>

    <!-- 编辑用户弹窗 -->
    <EditUserModal
      v-model:show="showEditUserModal"
      :user="selectedUser"
      @success="loadUsers"
    />
  </div>
</template>

<script setup>
import { ref, h, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import {
  NCard, NSpace, NGrid, NGi, NStatistic, NIcon, NTabs, NTabPane,
  NSpin, NList, NListItem, NThing, NTag, NButton, NEmpty, NProgress,
  NInput, NDataTable, NText, useMessage
} from 'naive-ui'
import {
  PeopleOutline, DocumentTextOutline, DownloadOutline, PulseOutline,
  SearchOutline
} from '@vicons/ionicons5'
import EditUserModal from '../components/EditUserModal.vue'
import UserAvatar from '../components/UserAvatar.vue'
import api from '../api/request'

const router = useRouter()
const message = useMessage()

const loading = ref(false)
const stats = ref({
  totalUsers: 0,
  totalFiles: 0,
  totalDownloads: 0,
  onlineUsers: 0,
  topFiles: [],
  topUploaders: [],
  downloadTrend: []
})

const users = ref([])
const userSearchKeyword = ref('')
const showEditUserModal = ref(false)
const selectedUser = ref(null)

const maxTrendCount = computed(() => {
  if (!stats.value.downloadTrend || stats.value.downloadTrend.length === 0) return 1
  return Math.max(...stats.value.downloadTrend.map(item => item.count))
})

const userColumns = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '用户名', key: 'username' },
  { title: '邮箱', key: 'email' },
  {
    title: '角色',
    key: 'role_name',
    render: (row) => h(
      NTag,
      { type: row.role_name === 'admin' ? 'error' : 'info' },
      { default: () => row.role_display_name }
    )
  },
  {
    title: '存储使用',
    key: 'storage_used',
    render: (row) => {
      const percent = Math.round((row.storage_used / row.storage_quota) * 100)
      return h(NText, null, { default: () => `${percent}%` })
    }
  },
  {
    title: '操作',
    key: 'actions',
    render: (row) => h(
      NButton,
      {
        size: 'small',
        onClick: () => editUser(row)
      },
      { default: () => '编辑' }
    )
  }
]

function getRankType(index) {
  if (index === 0) return 'error'
  if (index === 1) return 'warning'
  if (index === 2) return 'info'
  return 'default'
}

function getTrendPercent(count) {
  return Math.round((count / maxTrendCount.value) * 100)
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

async function loadStats() {
  loading.value = true
  try {
    const response = await api.get('/admin/stats')
    stats.value = response.stats
  } catch (error) {
    message.error('加载统计数据失败')
  } finally {
    loading.value = false
  }
}

async function loadUsers() {
  loading.value = true
  try {
    const response = await api.get('/admin/users', {
      params: { search: userSearchKeyword.value }
    })
    users.value = response.users || []
  } catch (error) {
    message.error('加载用户列表失败')
  } finally {
    loading.value = false
  }
}

function editUser(user) {
  selectedUser.value = user
  showEditUserModal.value = true
}

onMounted(() => {
  loadStats()
  loadUsers()
})
</script>

<style scoped>
.admin-container {
  max-width: 1400px;
  margin: 0 auto;
}
</style>
