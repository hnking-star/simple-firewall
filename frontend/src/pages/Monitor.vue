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
      <div class="pagination-bar">
        <span>共 {{ total }} 条，第 {{ page }} / {{ totalPages }} 页</span>
        <label>
          每页
          <select v-model.number="pageSize" @change="changePageSize">
            <option :value="10">10</option>
            <option :value="20">20</option>
            <option :value="50">50</option>
            <option :value="100">100</option>
          </select>
        </label>
        <button class="secondary" :disabled="page <= 1" @click="goPage(page - 1)">上一页</button>
        <button class="secondary" :disabled="page >= totalPages" @click="goPage(page + 1)">下一页</button>
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
            <td><span :class="['action-badge', packet.action === 'DENY' ? 'deny' : 'allow']">{{ packet.action }}</span></td>
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
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const totalPages = ref(1)
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
    const { data } = await api.get('/traffic/recent', {
      params: { page: page.value, page_size: pageSize.value },
    })
    traffic.value = data.items || []
    total.value = data.total || 0
    totalPages.value = data.total_pages || 1
    page.value = data.page || page.value
  } catch (err) {
    error.value = errorMessage(err, '最近数据包加载失败')
  }
}

function goPage(nextPage) {
  page.value = nextPage
  loadTraffic()
}

function changePageSize() {
  page.value = 1
  loadTraffic()
}

async function loadSnifferStatus() {
  try {
    const { data } = await api.get('/sniffer/status')
    running.value = Boolean(data.running)
  } catch (err) {
    error.value = errorMessage(err, '抓包状态加载失败')
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
  loadSnifferStatus()
  loadTraffic()
})
</script>
