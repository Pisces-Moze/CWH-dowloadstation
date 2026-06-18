<template>
  <n-modal
    v-model:show="showModal"
    preset="card"
    title="编辑用户"
    style="width: 500px"
    :bordered="false"
  >
    <n-spin :show="loading">
      <n-form
        ref="formRef"
        :model="formData"
        label-placement="left"
        label-width="100"
      >
        <n-form-item label="用户名">
          <n-input :value="user?.username" disabled />
        </n-form-item>

        <n-form-item label="邮箱">
          <n-input :value="user?.email" disabled />
        </n-form-item>

        <n-form-item label="角色">
          <n-select
            v-model:value="formData.roleId"
            :options="roleOptions"
            :loading="rolesLoading"
          />
        </n-form-item>

        <n-form-item label="存储配额">
          <n-input-number
            v-model:value="formData.quotaGB"
            :min="1"
            :max="100"
            style="width: 100%"
          >
            <template #suffix>GB</template>
          </n-input-number>
        </n-form-item>

        <n-form-item label="当前使用">
          <n-progress
            type="line"
            :percentage="storagePercent"
            :status="storageStatus"
          >
            {{ formatBytes(user?.storage_used) }} / {{ formatBytes(user?.storage_quota) }}
          </n-progress>
        </n-form-item>
      </n-form>
    </n-spin>

    <template #footer>
      <n-space justify="end">
        <n-button @click="showModal = false">取消</n-button>
        <n-button
          type="primary"
          :loading="loading"
          @click="handleSave"
        >
          保存
        </n-button>
        <n-popconfirm
          v-if="canDelete"
          @positive-click="handleDelete"
        >
          <template #trigger>
            <n-button type="error">
              删除用户
            </n-button>
          </template>
          确定要删除这个用户吗？此操作不可恢复！
        </n-popconfirm>
      </n-space>
    </template>
  </n-modal>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import {
  NModal, NSpin, NForm, NFormItem, NInput, NSelect, NInputNumber,
  NProgress, NSpace, NButton, NPopconfirm, useMessage
} from 'naive-ui'
import { useUserStore } from '../stores/user'
import api from '../api/request'

const props = defineProps({
  show: Boolean,
  user: Object
})

const emit = defineEmits(['update:show', 'success'])

const message = useMessage()
const userStore = useUserStore()

const showModal = computed({
  get: () => props.show,
  set: (val) => emit('update:show', val)
})

const formRef = ref(null)
const loading = ref(false)
const rolesLoading = ref(false)
const roleOptions = ref([])

const formData = ref({
  roleId: null,
  quotaGB: 3
})

const storagePercent = computed(() => {
  if (!props.user) return 0
  return Math.round((props.user.storage_used / props.user.storage_quota) * 100)
})

const storageStatus = computed(() => {
  const percent = storagePercent.value
  if (percent >= 90) return 'error'
  if (percent >= 70) return 'warning'
  return 'success'
})

const canDelete = computed(() => {
  return props.user && props.user.id !== userStore.user?.id
})

watch(() => props.user, (newUser) => {
  if (newUser) {
    formData.value.roleId = newUser.role_id
    formData.value.quotaGB = Math.round(newUser.storage_quota / (1024 * 1024 * 1024))
  }
})

watch(() => props.show, async (show) => {
  if (show && roleOptions.value.length === 0) {
    await loadRoles()
  }
})

async function loadRoles() {
  rolesLoading.value = true
  try {
    const response = await api.get('/admin/roles')
    roleOptions.value = response.roles.map(role => ({
      label: role.display_name,
      value: role.id
    }))
  } catch (error) {
    message.error('加载角色列表失败')
  } finally {
    rolesLoading.value = false
  }
}

async function handleSave() {
  loading.value = true
  try {
    // 更新角色
    await api.put(`/admin/users/${props.user.id}/role`, {
      roleId: formData.value.roleId
    })

    // 更新配额
    const quotaBytes = formData.value.quotaGB * 1024 * 1024 * 1024
    await api.put(`/admin/users/${props.user.id}/quota`, {
      quota: quotaBytes
    })

    message.success('保存成功')
    showModal.value = false
    emit('success')
  } catch (error) {
    message.error('保存失败')
  } finally {
    loading.value = false
  }
}

async function handleDelete() {
  loading.value = true
  try {
    await api.delete(`/admin/users/${props.user.id}`)
    message.success('删除成功')
    showModal.value = false
    emit('success')
  } catch (error) {
    message.error('删除失败')
  } finally {
    loading.value = false
  }
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}
</script>
