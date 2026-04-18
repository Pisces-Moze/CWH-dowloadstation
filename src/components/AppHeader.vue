<template>
  <header class="app-header">
    <div class="header-content">
      <div class="logo" @click="router.push('/')">
        <n-icon size="32" color="#667eea">
          <CloudDownloadOutline />
        </n-icon>
        <span class="logo-text">CWH 下载站</span>
      </div>

      <nav class="nav-menu">
        <n-space>
          <n-button text @click="router.push('/')">
            <template #icon>
              <n-icon><HomeOutline /></n-icon>
            </template>
            首页
          </n-button>

          <n-button v-if="userStore.isLoggedIn" text @click="router.push('/private')">
            <template #icon>
              <n-icon><LockClosedOutline /></n-icon>
            </template>
            私人空间
          </n-button>

          <n-button v-if="userStore.isAdmin" text @click="router.push('/admin')">
            <template #icon>
              <n-icon><SettingsOutline /></n-icon>
            </template>
            控制面板
          </n-button>
        </n-space>
      </nav>

      <div class="user-actions">
        <n-space v-if="userStore.isLoggedIn">
          <n-badge :value="userStore.storagePercent + '%'" :type="storageType">
            <n-button circle @click="router.push('/profile')">
              <template #icon>
                <n-avatar
                  v-if="userStore.avatarUrl"
                  :src="userStore.avatarUrl"
                  size="small"
                />
                <n-icon v-else><PersonOutline /></n-icon>
              </template>
            </n-button>
          </n-badge>

          <n-dropdown :options="userMenuOptions" @select="handleUserMenuSelect">
            <n-button>
              {{ userStore.username }}
              <template #icon>
                <n-icon><ChevronDownOutline /></n-icon>
              </template>
            </n-button>
          </n-dropdown>
        </n-space>

        <n-space v-else>
          <n-button @click="router.push('/login')">登录</n-button>
          <n-button type="primary" @click="router.push('/register')">注册</n-button>
        </n-space>
      </div>
    </div>
  </header>
</template>

<script setup>
import { computed, h } from 'vue'
import { useRouter } from 'vue-router'
import { 
  NButton, NSpace, NIcon, NAvatar, NDropdown, NBadge,
  useDialog
} from 'naive-ui'
import {
  CloudDownloadOutline,
  HomeOutline,
  LockClosedOutline,
  SettingsOutline,
  PersonOutline,
  ChevronDownOutline,
  PersonCircleOutline,
  LogOutOutline
} from '@vicons/ionicons5'
import { useUserStore } from '../stores/user'

const router = useRouter()
const userStore = useUserStore()
const dialog = useDialog()

const storageType = computed(() => {
  const percent = userStore.storagePercent
  if (percent >= 90) return 'error'
  if (percent >= 70) return 'warning'
  return 'success'
})

const userMenuOptions = [
  {
    label: '个人资料',
    key: 'profile',
    icon: () => h(NIcon, null, { default: () => h(PersonCircleOutline) })
  },
  {
    label: '退出登录',
    key: 'logout',
    icon: () => h(NIcon, null, { default: () => h(LogOutOutline) })
  }
]

function handleUserMenuSelect(key) {
  if (key === 'profile') {
    router.push('/profile')
  } else if (key === 'logout') {
    dialog.warning({
      title: '确认退出',
      content: '确定要退出登录吗？',
      positiveText: '确定',
      negativeText: '取消',
      onPositiveClick: () => {
        userStore.logout()
        router.push('/')
      }
    })
  }
}
</script>

<style scoped>
.app-header {
  background: white;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  position: sticky;
  top: 0;
  z-index: 1000;
}

.header-content {
  max-width: 1400px;
  margin: 0 auto;
  padding: 16px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
}

.logo {
  display: flex;
  align-items: center;
  gap: 12px;
  cursor: pointer;
  user-select: none;
}

.logo-text {
  font-size: 20px;
  font-weight: 600;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.nav-menu {
  flex: 1;
  display: flex;
  justify-content: center;
}

@media (max-width: 768px) {
  .header-content {
    padding: 12px 10px;
  }

  .logo-text {
    display: none;
  }

  .nav-menu {
    display: none;
  }
}
</style>
