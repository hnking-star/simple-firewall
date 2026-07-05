<template>
  <section>
    <h2 class="page-title">首页概览</h2>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="grid stats-grid">
      <div v-for="item in statItems" :key="item.key" class="card stat-card">
        <div class="stat-label">{{ item.label }}</div>
        <div class="stat-value">{{ stats[item.key] }}</div>
      </div>
    </div>

    <div class="chart-row">
      <div class="card">
        <h3>安全态势</h3>
        <div ref="gaugeEl" class="chart"></div>
      </div>
      <div class="card">
        <h3>处理结果统计</h3>
        <div ref="barEl" class="chart"></div>
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
const error = ref('')
const gaugeEl = ref(null)
const barEl = ref(null)
let gaugeChart = null
let barChart = null
let timer = null
let alive = false

const statItems = [
  { key: 'blocked_count', label: '拦截数量' },
  { key: 'allowed_count', label: '放行数量' },
  { key: 'active_connections', label: '活跃连接' },
  { key: 'enabled_rules', label: '启用规则' },
]

const totalPackets = computed(() => stats.value.blocked_count + stats.value.allowed_count)
const blockedRate = computed(() => {
  if (!totalPackets.value) return 0
  return Number(((stats.value.blocked_count / totalPackets.value) * 100).toFixed(2))
})

function initCharts() {
  if (!alive) return
  if (!gaugeChart && gaugeEl.value) {
    gaugeChart = echarts.init(gaugeEl.value)
  }
  if (!barChart && barEl.value) {
    barChart = echarts.init(barEl.value)
  }
}

function renderCharts() {
  if (!alive) return
  initCharts()
  if (gaugeChart) {
    gaugeChart.setOption({
      tooltip: { formatter: ({ value }) => `拦截占比：${Number(value).toFixed(2)}%` },
      series: [
        {
          name: '拦截占比',
          type: 'gauge',
          min: 0,
          max: 100,
          radius: '82%',
          progress: { show: true, width: 14 },
          axisLine: { lineStyle: { width: 14 } },
          axisTick: { show: false },
          splitLine: { length: 12, lineStyle: { width: 2 } },
          pointer: { width: 5 },
          title: { offsetCenter: [0, '64%'], fontSize: 16 },
          detail: {
            valueAnimation: true,
            formatter: (value) => `${Number(value).toFixed(2)}%`,
            fontSize: 30,
            offsetCenter: [0, '32%'],
          },
          data: [{ value: blockedRate.value, name: '拦截占比' }],
        },
      ],
    })
  }
  if (barChart) {
    barChart.setOption({
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { left: 80, right: 32, top: 32, bottom: 32 },
      xAxis: { type: 'value' },
      yAxis: { type: 'category', data: ['拦截', '放行', '启用规则'] },
      series: [
        {
          type: 'bar',
          barWidth: 28,
          data: [
            { value: stats.value.blocked_count, itemStyle: { color: '#ef4444' } },
            { value: stats.value.allowed_count, itemStyle: { color: '#22c55e' } },
            { value: stats.value.enabled_rules, itemStyle: { color: '#2563eb' } },
          ],
          label: { show: true, position: 'right' },
        },
      ],
    })
  }
}

async function loadStats() {
  try {
    const { data } = await api.get('/stats')
    if (!alive) return
    stats.value = { ...stats.value, ...data }
    error.value = ''
    await nextTick()
    if (!alive) return
    renderCharts()
  } catch (err) {
    if (!alive) return
    error.value = errorMessage(err, '统计加载失败')
  }
}

function resizeCharts() {
  if (!alive) return
  gaugeChart?.resize()
  barChart?.resize()
}

onMounted(() => {
  alive = true
  loadStats()
  timer = window.setInterval(loadStats, 2000)
  window.addEventListener('resize', resizeCharts)
})

onBeforeUnmount(() => {
  alive = false
  window.clearInterval(timer)
  window.removeEventListener('resize', resizeCharts)
  gaugeChart?.dispose()
  barChart?.dispose()
  gaugeChart = null
  barChart = null
})
</script>
