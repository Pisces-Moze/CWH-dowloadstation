<template>
  <div class="user-avatar-wrapper" :style="{ width: size + 'px', height: size + 'px' }">
    <n-avatar
      :size="size"
      :src="src"
      round
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
      :class="`status-${currentStatus}`"
      :style="{
        width: dotSize + 'px',
        height: dotSize + 'px'
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

const statusText = computed(() => getStatusText(currentStatus.value))
const dotSize = computed(() => Math.max(10, props.size * 0.25))
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
  border: 2px solid #fff;
  z-index: 1;
  transition: all 0.3s ease;
}

/* 在线 - 蓝绿色炫光 */
.status-online {
  background: #18a058;
  box-shadow: 
    0 0 0 0 rgba(24, 160, 88, 0.4),
    0 0 8px rgba(24, 160, 88, 0.6),
    0 0 12px rgba(24, 160, 88, 0.4);
  animation: pulse-online 2s ease-in-out infinite;
}

@keyframes pulse-online {
  0%, 100% {
    box-shadow: 
      0 0 0 0 rgba(24, 160, 88, 0.4),
      0 0 8px rgba(24, 160, 88, 0.6),
      0 0 12px rgba(24, 160, 88, 0.4);
  }
  50% {
    box-shadow: 
      0 0 0 3px rgba(24, 160, 88, 0),
      0 0 12px rgba(24, 160, 88, 0.8),
      0 0 16px rgba(24, 160, 88, 0.6);
  }
}

/* 离开 - 黄色炫光 */
.status-away {
  background: #f0a020;
  box-shadow: 
    0 0 0 0 rgba(240, 160, 32, 0.4),
    0 0 8px rgba(240, 160, 32, 0.6),
    0 0 12px rgba(240, 160, 32, 0.4);
  animation: pulse-away 2s ease-in-out infinite;
}

@keyframes pulse-away {
  0%, 100% {
    box-shadow: 
      0 0 0 0 rgba(240, 160, 32, 0.4),
      0 0 8px rgba(240, 160, 32, 0.6),
      0 0 12px rgba(240, 160, 32, 0.4);
  }
  50% {
    box-shadow: 
      0 0 0 3px rgba(240, 160, 32, 0),
      0 0 12px rgba(240, 160, 32, 0.8),
      0 0 16px rgba(240, 160, 32, 0.6);
  }
}

/* 离线 - 红色无炫光 */
.status-offline {
  background: #d03050;
  box-shadow: 
    0 0 0 0 rgba(208, 48, 80, 0.3),
    0 0 4px rgba(208, 48, 80, 0.4);
}
</style>
