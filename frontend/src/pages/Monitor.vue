<template>
  <section>
    <h2 class="page-title">抓包监控</h2>
    <div class="card">
      <p>当前状态：<strong>{{ running ? '运行中' : '已停止' }}</strong></p>
      <div class="actions">
        <button :disabled="loading" @click="startSniffer">启动</button>
        <button class="secondary" :disabled="loading" @click="stopSniffer">停止</button>
        <span v-if="message" class="message">{{ message }}</span>
        <span v-if="error" class="error">{{ error }}</span>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref } from 'vue'
import api, { errorMessage } from '../api/client'

const running = ref(false)
const loading = ref(false)
const message = ref('')
const error = ref('')

async function setSniffer(path, successText) {
  loading.value = true
  message.value = ''
  error.value = ''
  try {
    const { data } = await api.post(path)
    running.value = Boolean(data.running)
    message.value = successText
  } catch (err) {
    error.value = errorMessage(err, '操作失败')
  } finally {
    loading.value = false
  }
}

function startSniffer() {
  setSniffer('/sniffer/start', '启动成功')
}

function stopSniffer() {
  setSniffer('/sniffer/stop', '停止成功')
}
</script>
