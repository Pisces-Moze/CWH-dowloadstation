<template>
  <div class="user-avatar-wrapper" :style="{ width: size + 'px', height: size + 'px' }">
    <n-avatar
      :size="size"
      :src="src"
      :round="round"
      :style="avatarStyle"
    >
      <template #fallback>
        <n-icon :size="size * 0.5">
          <PersonOutline />
        </n-icon>
      </template>
    </n-avatar>
    <div
      v-if="showStatus"
      class="status-dot"
      :style="{
        backgroundColor: statusColor,
        width: dotSize + 'px',
        height: dotSize + 'px',
        border: `${borderWidth}px solid #fff`,
        boxShadow: `0 0 0 1px ${statusColor}40`
      }"
      :title="statusText"
    />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { NAvatar, NIcon } from 'naive-ui'
import { PersonOutline } from '@vicons/ionicons5'
import { getUserStatus, getStatusColor, getStatusText } from '../utils/socket'

const props = defineProps({
  src: {
    type: String,
    default: ''
  },
  size: {
    type: Number,
    default: 40
  },
  round: {
    type: Boolean,
    default: true
  },
  userId: {
    type: [Number, String],
    default: null
  },
  showStatus: {
    type: Boolean,
    default: true
  },
  status: {
    type: String,
    default: null // 可以直接传入状态，不通过 WebSocket
  },
  avatarStyle: {
    type: Object,
    default: () => ({})
  }
})

const currentStatus = computed(() => {
  if (props.status) return props.status
  if (props.userId) return getUserStatus(props.userId)
  return 'offline'
})

const statusColor = computed(() => getStatusColor(currentStatus.value))
const statusText = computed(() => getStatusText(currentStatus.value))

const dotSize = computed(() => Math.max(8, props.size * 0.28))
const borderWidth = computed(() => Math.max(2, props.size * 0.05))
</script>

<style scoped>
.user-avatar-wrapper {
  position: relative;
  display: inline-flex;
  flex-shrink: 0;
}

.status-dot {
  position: absolute;
  top: 0;
  right: 0;
  border-radius: 50%;
  transition: background-color 0.3s ease;
  z-index: 1;
}
</style>
