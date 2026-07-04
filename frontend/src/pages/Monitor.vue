<template>
  <section>
    <h2 class="page-title">抓包监控</h2>
    <div class="card">
      <p>当前状态：<strong>{{ running ? '运行中' : '已停止' }}</strong></p>
      <p>当前网络接口：<strong>{{ networkInterface || '未配置' }}</strong></p>
      <div class="actions">
        <button :disabled="loading" @click="startSniffer">启动</button>
        <button class="secondary" :disabled="loading" @click="stopSniffer">停止</button>
        <span v-if="message" class="message">{{ message }}</span>
        <span v-if="error" class="error">{{ error }}</span>
      </div>
    </div>

    <div class="card table-wrap">
      <div class="section-header">
        <h3>最近数据包</h3>
        <button class="secondary" @click="loadTraffic">刷新</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th><th>时间</th><th>源</th><th>目标</th><th>协议</th><th>方向</th><th>动作</th><th>规则</th><th>长度</th><th>原因</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="packet in traffic" :key="packet.id">
            <td>{{ packet.id }}</td>
            <td>{{ packet.timestamp }}</td>
            <td>{{ packet.src_ip }}:{{ packet.src_port }}</td>
            <td>{{ packet.dst_ip }}:{{ packet.dst_port }}</td>
            <td>{{ packet.protocol }}</td>
            <td>{{ packet.direction }}</td>
            <td>{{ packet.action }}</td>
            <td>{{ packet.rule_id || '-' }}</td>
            <td>{{ packet.packet_len }}</td>
            <td>{{ packet.reason || '-' }}</td>
          </tr>
          <tr v-if="traffic.length === 0">
            <td colspan="10">暂无数据包</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import api, { errorMessage } from '../api/client'

const running = ref(false)
const loading = ref(false)
const networkInterface = ref('')
const traffic = ref([])
const message = ref('')
const error = ref('')

async function loadSettings() {
  try {
    const { data } = await api.get('/settings')
    networkInterface.value = data.interface || ''
  } catch (err) {
    error.value = errorMessage(err, '设置加载失败')
  }
}

async function loadTraffic() {
  try {
    const { data } = await api.get('/traffic/recent')
    traffic.value = data.items || []
  } catch (err) {
    error.value = errorMessage(err, '最近数据包加载失败')
  }
}

async function setSniffer(path, successText) {
  loading.value = true
  message.value = ''
  error.value = ''
  try {
    const { data } = await api.post(path)
    running.value = Boolean(data.running)
    message.value = `${successText}，当前状态：${running.value ? '运行中' : '已停止'}`
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

onMounted(() => {
  loadSettings()
  loadTraffic()
})
</script>
