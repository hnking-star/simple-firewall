<template>
  <section>
    <h2 class="page-title">首页概览</h2>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="grid stats-grid">
      <div v-for="item in statItems" :key="item.key" class="card">
        <div>{{ item.label }}</div>
        <div class="stat-value">{{ stats[item.key] }}</div>
      </div>
    </div>

    <div class="chart-row">
      <div class="card">
        <h3>访问趋势</h3>
        <div ref="lineEl" class="chart"></div>
      </div>
      <div class="card">
        <h3>拦截占比</h3>
        <div ref="pieEl" class="chart"></div>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import * as echarts from 'echarts'
import api, { errorMessage } from '../api/client'

const stats = ref({
  blocked_count: 0,
  allowed_count: 0,
  active_connections: 0,
  enabled_rules: 0,
})
const history = ref([])
const error = ref('')
const lineEl = ref(null)
const pieEl = ref(null)
let lineChart = null
let pieChart = null
let timer = null

const statItems = [
  { key: 'blocked_count', label: '拦截数量' },
  { key: 'allowed_count', label: '放行数量' },
  { key: 'active_connections', label: '活跃连接' },
  { key: 'enabled_rules', label: '启用规则' },
]

const labels = computed(() => history.value.map((item) => item.time))

function initCharts() {
  if (!lineChart && lineEl.value) {
    lineChart = echarts.init(lineEl.value)
  }
  if (!pieChart && pieEl.value) {
    pieChart = echarts.init(pieEl.value)
  }
}

function renderCharts() {
  initCharts()
  if (lineChart) {
    lineChart.setOption({
      tooltip: { trigger: 'axis' },
      legend: { data: ['拦截', '放行'] },
      xAxis: { type: 'category', data: labels.value },
      yAxis: { type: 'value' },
      series: [
        { name: '拦截', type: 'line', data: history.value.map((item) => item.blocked) },
        { name: '放行', type: 'line', data: history.value.map((item) => item.allowed) },
      ],
    })
  }
  if (pieChart) {
    pieChart.setOption({
      tooltip: { trigger: 'item' },
      series: [
        {
          type: 'pie',
          radius: '60%',
          data: [
            { name: '拦截', value: stats.value.blocked_count },
            { name: '放行', value: stats.value.allowed_count },
          ],
        },
      ],
    })
  }
}

async function loadStats() {
  try {
    const { data } = await api.get('/stats')
    stats.value = { ...stats.value, ...data }
    history.value.push({
      time: new Date().toLocaleTimeString(),
      blocked: stats.value.blocked_count,
      allowed: stats.value.allowed_count,
    })
    history.value = history.value.slice(-12)
    error.value = ''
    await nextTick()
    renderCharts()
  } catch (err) {
    error.value = errorMessage(err, '统计加载失败')
  }
}

function resizeCharts() {
  lineChart?.resize()
  pieChart?.resize()
}

onMounted(() => {
  loadStats()
  timer = window.setInterval(loadStats, 2000)
  window.addEventListener('resize', resizeCharts)
})

onBeforeUnmount(() => {
  window.clearInterval(timer)
  window.removeEventListener('resize', resizeCharts)
  lineChart?.dispose()
  pieChart?.dispose()
})
</script>
