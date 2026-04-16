<template>
  <div id="app">
    <n-config-provider :theme="theme">
      <n-message-provider>
        <router-view />
      </n-message-provider>
    </n-config-provider>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { NConfigProvider, NMessageProvider } from 'naive-ui'

const theme = ref(null)
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

#app {
  min-height: 100vh;
}
</style>
