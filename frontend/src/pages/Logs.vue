<template>
  <section>
    <h2 class="page-title">日志审计</h2>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="card">
      <div class="grid form-grid">
        <label>
          动作
          <select v-model="filters.action">
            <option value="">全部</option>
            <option v-for="action in actionOptions" :key="action" :value="action">{{ action }}</option>
          </select>
        </label>
        <label>
          协议
          <select v-model="filters.protocol">
            <option value="">全部</option>
            <option v-for="protocol in protocolOptions" :key="protocol" :value="protocol">{{ protocol }}</option>
          </select>
        </label>
        <label>
          IP 关键词
          <input v-model.trim="filters.ip" placeholder="源或目标 IP" />
        </label>
      </div>
      <div class="actions">
        <button class="secondary" @click="loadLogs">刷新</button>
        <button @click="exportCsv">导出 CSV</button>
      </div>
    </div>

    <div class="card table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th><th>时间</th><th>源</th><th>目标</th><th>协议</th><th>方向</th><th>动作</th><th>规则</th><th>长度</th><th>原因</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="log in filteredLogs" :key="log.id">
            <td>{{ log.id }}</td>
            <td>{{ log.timestamp }}</td>
            <td>{{ log.src_ip }}:{{ log.src_port }}</td>
            <td>{{ log.dst_ip }}:{{ log.dst_port }}</td>
            <td>{{ log.protocol }}</td>
            <td>{{ log.direction }}</td>
            <td><span :class="['action-badge', log.action === 'DENY' ? 'deny' : 'allow']">{{ log.action }}</span></td>
            <td>{{ log.rule_id || '-' }}</td>
            <td>{{ log.packet_len }}</td>
            <td>{{ log.reason || '-' }}</td>
          </tr>
          <tr v-if="filteredLogs.length === 0">
            <td colspan="10">暂无日志</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import api, { errorMessage } from '../api/client'

const logs = ref([])
const filters = ref({
  action: '',
  protocol: '',
  ip: '',
})
const error = ref('')

const actionOptions = computed(() => uniqueValues('action'))
const protocolOptions = computed(() => uniqueValues('protocol'))
const filteredLogs = computed(() => logs.value.filter((log) => {
  const ipKeyword = filters.value.ip.toLowerCase()
  const matchesAction = !filters.value.action || log.action === filters.value.action
  const matchesProtocol = !filters.value.protocol || log.protocol === filters.value.protocol
  const matchesIp = !ipKeyword
    || String(log.src_ip || '').toLowerCase().includes(ipKeyword)
    || String(log.dst_ip || '').toLowerCase().includes(ipKeyword)
  return matchesAction && matchesProtocol && matchesIp
}))

function uniqueValues(key) {
  return [...new Set(logs.value.map((log) => log[key]).filter(Boolean))]
}

async function loadLogs() {
  try {
    const { data } = await api.get('/logs')
    logs.value = data.items || []
  } catch (err) {
    error.value = errorMessage(err, '日志加载失败')
  }
}

function csvValue(value) {
  const text = String(value ?? '')
  return `"${text.replaceAll('"', '""')}"`
}

function exportCsv() {
  const columns = [
    ['id', 'ID'],
    ['timestamp', '时间'],
    ['src_ip', '源 IP'],
    ['src_port', '源端口'],
    ['dst_ip', '目标 IP'],
    ['dst_port', '目标端口'],
    ['protocol', '协议'],
    ['direction', '方向'],
    ['action', '动作'],
    ['rule_id', '规则'],
    ['packet_len', '长度'],
    ['reason', '原因'],
  ]
  const rows = [
    columns.map(([, label]) => csvValue(label)).join(','),
    ...filteredLogs.value.map((log) => columns.map(([key]) => csvValue(log[key])).join(',')),
  ]
  const blob = new Blob([`\uFEFF${rows.join('\n')}`], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'traffic-logs.csv'
  link.click()
  URL.revokeObjectURL(url)
}

onMounted(loadLogs)
</script>
