<template>
  <section>
    <h2 class="page-title">系统设置</h2>
    <div class="card">
      <div class="grid form-grid">
        <label>
          网络接口
          <input v-model="form.interface" />
        </label>
        <label>
          更新模式
          <select v-model="form.update_mode">
            <option value="immediate">立即更新</option>
            <option value="timed">定时更新</option>
            <option value="counted">按数量更新</option>
          </select>
        </label>
        <label>
          更新间隔
          <input v-model="form.update_interval" type="number" min="1" />
        </label>
        <label>
          批量大小
          <input v-model="form.update_batch_size" type="number" min="1" />
        </label>
        <label>
          启用 iptables
          <select v-model="form.iptables_enabled">
            <option value="true">是</option>
            <option value="false">否</option>
          </select>
        </label>
        <label>
          启用抓包
          <select v-model="form.sniffer_enabled">
            <option value="true">是</option>
            <option value="false">否</option>
          </select>
        </label>
      </div>
      <div class="actions">
        <button @click="saveSettings">保存</button>
        <span v-if="message" class="message">{{ message }}</span>
        <span v-if="error" class="error">{{ error }}</span>
      </div>
    </div>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import api, { errorMessage } from '../api/client'

const form = ref({
  interface: '',
  update_mode: 'immediate',
  update_interval: '',
  update_batch_size: '',
  iptables_enabled: 'false',
  sniffer_enabled: 'false',
})
const message = ref('')
const error = ref('')

function boolSetting(value) {
  return value === true || value === 'true' || value === '1' ? 'true' : 'false'
}

function pickSettings(data) {
  form.value = {
    interface: data.interface || '',
    update_mode: data.update_mode || 'immediate',
    update_interval: data.update_interval || '',
    update_batch_size: data.update_batch_size || '',
    iptables_enabled: boolSetting(data.iptables_enabled),
    sniffer_enabled: boolSetting(data.sniffer_enabled),
  }
}

async function loadSettings() {
  try {
    const { data } = await api.get('/settings')
    pickSettings(data)
  } catch (err) {
    error.value = errorMessage(err, '设置加载失败')
  }
}

async function saveSettings() {
  message.value = ''
  error.value = ''
  try {
    const { data } = await api.put('/settings', form.value)
    pickSettings(data)
    message.value = '保存成功'
  } catch (err) {
    error.value = errorMessage(err, '保存失败')
  }
}

onMounted(loadSettings)
</script>
