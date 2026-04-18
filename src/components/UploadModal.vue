<template>
  <n-modal
    v-model:show="showModal"
    preset="card"
    :title="isPrivate ? '上传到私人空间' : '上传文件'"
    style="width: 600px"
    :bordered="false"
  >
    <n-space vertical size="large">
      <n-upload
        ref="uploadRef"
        :action="uploadUrl"
        :headers="uploadHeaders"
        :data="uploadData"
        :max="5"
        :show-file-list="true"
        @before-upload="handleBeforeUpload"
        @finish="handleFinish"
        @error="handleError"
      >
        <n-upload-dragger>
          <div style="margin-bottom: 12px">
            <n-icon size="48" :depth="3">
              <CloudUploadOutline />
            </n-icon>
          </div>
          <n-text style="font-size: 16px">
            点击或拖拽文件到此区域上传
          </n-text>
          <n-p depth="3" style="margin: 8px 0 0 0">
            最多同时上传 5 个文件，单个文件最大 100MB
          </n-p>
        </n-upload-dragger>
      </n-upload>

      <n-alert v-if="isPrivate" type="info">
        文件将加密存储在您的私人空间，只有您可以访问
      </n-alert>

      <n-alert v-else type="warning">
        上传到公共空间的文件所有人都可以下载
      </n-alert>
    </n-space>

    <template #footer>
      <n-space justify="end">
        <n-button @click="showModal = false">关闭</n-button>
      </n-space>
    </template>
  </n-modal>
</template>

<script setup>
import { ref, computed } from 'vue'
import {
  NModal, NSpace, NUpload, NUploadDragger, NIcon, NText, NP,
  NAlert, NButton, useMessage
} from 'naive-ui'
import { CloudUploadOutline } from '@vicons/ionicons5'

const props = defineProps({
  show: Boolean,
  isPrivate: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['update:show', 'success'])

const message = useMessage()

const showModal = computed({
  get: () => props.show,
  set: (val) => emit('update:show', val)
})

const uploadRef = ref(null)

const uploadUrl = computed(() => {
  return '/api/files/upload'
})

const uploadHeaders = computed(() => {
  const token = localStorage.getItem('token')
  return {
    Authorization: `Bearer ${token}`
  }
})

const uploadData = computed(() => {
  return {
    isPrivate: props.isPrivate
  }
})

function handleBeforeUpload(data) {
  const { file } = data
  const maxSize = 100 * 1024 * 1024 // 100MB

  if (file.file.size > maxSize) {
    message.error('文件大小不能超过 100MB')
    return false
  }

  return true
}

function handleFinish({ file, event }) {
  try {
    const response = JSON.parse(event.target.response)
    if (response.success) {
      message.success(`${file.name} 上传成功`)
      emit('success')
    } else {
      message.error(`${file.name} 上传失败: ${response.message}`)
    }
  } catch (error) {
    message.error(`${file.name} 上传失败`)
  }
}

function handleError({ file }) {
  message.error(`${file.name} 上传失败`)
}
</script>
