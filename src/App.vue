<template>
  <n-config-provider :theme="theme">
    <n-message-provider>
      <n-dialog-provider>
        <n-notification-provider>
          <div id="app">
            <AppHeader v-if="!isSharePage" />
            <main class="main-content">
              <router-view />
            </main>
            <AppFooter v-if="!isSharePage" />
          </div>
        </n-notification-provider>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { NConfigProvider, NMessageProvider, NDialogProvider, NNotificationProvider, darkTheme } from 'naive-ui'
import AppHeader from './components/AppHeader.vue'
import AppFooter from './components/AppFooter.vue'
import { useUserStore } from './stores/user'

const route = useRoute()
const userStore = useUserStore()

const theme = null // 使用亮色主题，如需暗色主题改为 darkTheme
const isSharePage = computed(() => route.name === 'Share')

onMounted(async () => {
  if (userStore.isLoggedIn && !userStore.user) {
    await userStore.fetchProfile()
  }
})
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background: #f5f7fa;
}

#app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.main-content {
  flex: 1;
  padding: 20px;
  max-width: 1400px;
  width: 100%;
  margin: 0 auto;
}

@media (max-width: 768px) {
  .main-content {
    padding: 10px;
  }
}
</style>
