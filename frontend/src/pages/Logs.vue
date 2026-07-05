<template>
  <section>
    <h2 class="page-title">日志审计</h2>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="card">
      <div class="grid form-grid">
        <label>
          级别
          <select v-model="filters.level">
            <option value="">全部</option>
            <option v-for="level in levelOptions" :key="level" :value="level">{{ level }}</option>
          </select>
        </label>
        <label>
          模块
          <select v-model="filters.module">
            <option value="">全部</option>
            <option v-for="module in moduleOptions" :key="module" :value="module">{{ module }}</option>
          </select>
        </label>
        <label>
          关键词
          <input v-model.trim="filters.keyword" placeholder="搜索操作内容" />
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
            <th>ID</th><th>时间</th><th>级别</th><th>模块</th><th>操作内容</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="log in filteredLogs" :key="log.id">
            <td>{{ log.id }}</td>
            <td>{{ log.timestamp }}</td>
            <td><span :class="['level-badge', String(log.level).toLowerCase()]">{{ log.level }}</span></td>
            <td>{{ log.module || '-' }}</td>
            <td>{{ log.message }}</td>
          </tr>
          <tr v-if="filteredLogs.length === 0">
            <td colspan="5">暂无日志</td>
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
const filters = ref({ level: '', module: '', keyword: '' })
const error = ref('')

const levelOptions = computed(() => uniqueValues('level'))
const moduleOptions = computed(() => uniqueValues('module'))
const filteredLogs = computed(() => logs.value.filter((log) => {
  const keyword = filters.value.keyword.toLowerCase()
  const matchesLevel = !filters.value.level || log.level === filters.value.level
  const matchesModule = !filters.value.module || log.module === filters.value.module
  const matchesKeyword = !keyword || String(log.message || '').toLowerCase().includes(keyword)
  return matchesLevel && matchesModule && matchesKeyword
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
    ['id', 'ID'], ['timestamp', '时间'], ['level', '级别'],
    ['module', '模块'], ['message', '操作内容'],
  ]
  const rows = [
    columns.map(([, label]) => csvValue(label)).join(','),
    ...filteredLogs.value.map((log) => columns.map(([key]) => csvValue(log[key])).join(',')),
  ]
  const blob = new Blob([`\uFEFF${rows.join('\n')}`], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'system-audit-logs.csv'
  link.click()
  URL.revokeObjectURL(url)
}

onMounted(loadLogs)
</script>
