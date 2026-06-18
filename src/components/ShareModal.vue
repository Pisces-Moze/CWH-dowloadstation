<template>
  <n-modal
    v-model:show="showModal"
    preset="card"
    title="创建分享链接"
    style="width: 500px"
    :bordered="false"
  >
    <n-form
      ref="formRef"
      :model="formData"
      label-placement="left"
      label-width="100"
    >
      <n-form-item label="过期时间">
        <n-select
          v-model:value="formData.expireType"
          :options="expireOptions"
        />
      </n-form-item>

      <n-form-item v-if="formData.expireType === 'custom'" label="自定义时间">
        <n-date-picker
          v-model:value="formData.customExpireTime"
          type="datetime"
          clearable
        />
      </n-form-item>

      <n-form-item label="访问密码">
        <n-input
          v-model:value="formData.password"
          placeholder="留空则无需密码"
          maxlength="20"
          show-count
        />
      </n-form-item>

      <n-form-item label="下载次数限制">
        <n-input-number
          v-model:value="formData.maxDownloads"
          :min="0"
          placeholder="0 表示不限制"
          style="width: 100%"
        />
      </n-form-item>
    </n-form>

    <template #footer>
      <n-space justify="end">
        <n-button @click="showModal = false">取消</n-button>
        <n-button
          type="primary"
          :loading="loading"
          @click="handleCreate"
        >
          创建
        </n-button>
      </n-space>
    </template>
  </n-modal>

  <!-- 分享链接结果弹窗 -->
  <n-modal
    v-model:show="showResultModal"
    preset="card"
    title="分享链接已创建"
    style="width: 500px"
    :bordered="false"
  >
    <n-space vertical>
      <n-alert type="success">
        分享链接创建成功！
      </n-alert>

      <n-input
        :value="shareUrl"
        readonly
      >
        <template #suffix>
          <n-button text @click="copyShareUrl">
            <template #icon>
              <n-icon><CopyOutline /></n-icon>
            </template>
            复制
          </n-button>
        </template>
      </n-input>

      <n-descriptions v-if="shareInfo" :column="1" bordered size="small">
        <n-descriptions-item label="分享码">
          {{ shareInfo.shareCode }}
        </n-descriptions-item>
        <n-descriptions-item v-if="shareInfo.password" label="访问密码">
          {{ shareInfo.password }}
        </n-descriptions-item>
        <n-descriptions-item v-if="shareInfo.expiresAt" label="过期时间">
          {{ formatDate(shareInfo.expiresAt) }}
        </n-descriptions-item>
        <n-descriptions-item v-if="shareInfo.maxDownloads" label="下载限制">
          {{ shareInfo.maxDownloads }} 次
        </n-descriptions-item>
      </n-descriptions>
    </n-space>

    <template #footer>
      <n-space justify="end">
        <n-button type="primary" @click="showResultModal = false">
          关闭
        </n-button>
      </n-space>
    </template>
  </n-modal>
</template>

<script setup>
import { ref, computed } from 'vue'
import {
  NModal, NForm, NFormItem, NSelect, NDatePicker, NInput, NInputNumber,
  NSpace, NButton, NAlert, NDescriptions, NDescriptionsItem, NIcon, useMessage
} from 'naive-ui'
import { CopyOutline } from '@vicons/ionicons5'
import api from '../api/request'

const props = defineProps({
  show: Boolean,
  fileId: Number
})

const emit = defineEmits(['update:show'])

const message = useMessage()

const showModal = computed({
  get: () => props.show,
  set: (val) => emit('update:show', val)
})

const formRef = ref(null)
const loading = ref(false)
const showResultModal = ref(false)
const shareInfo = ref(null)

const formData = ref({
  expireType: '1month',
  customExpireTime: null,
  password: '',
  maxDownloads: 0
})

const expireOptions = [
  { label: '一个月', value: '1month' },
  { label: '一年', value: '1year' },
  { label: '永久有效', value: 'never' },
  { label: '自定义', value: 'custom' }
]

const shareUrl = computed(() => {
  if (!shareInfo.value) return ''
  return `${window.location.origin}/share/${shareInfo.value.shareCode}`
})

async function handleCreate() {
  loading.value = true
  try {
    const data = {
      expireType: formData.value.expireType,
      password: formData.value.password || undefined,
      maxDownloads: formData.value.maxDownloads || undefined
    }

    if (formData.value.expireType === 'custom' && formData.value.customExpireTime) {
      data.customExpireTime = new Date(formData.value.customExpireTime).toISOString()
    }

    const response = await api.post(`/files/share/${props.fileId}`, data)
    shareInfo.value = response.share
    showModal.value = false
    showResultModal.value = true
    message.success('分享链接创建成功')
  } catch (error) {
    message.error('创建分享链接失败')
  } finally {
    loading.value = false
  }
}

function copyShareUrl() {
  navigator.clipboard.writeText(shareUrl.value)
  message.success('已复制到剪贴板')
}

function formatDate(dateString) {
  if (!dateString) return '-'
  const date = new Date(dateString)
  return date.toLocaleString('zh-CN')
}
</script>
