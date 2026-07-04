<template>
  <section>
    <h2 class="page-title">日志审计</h2>
    <p v-if="error" class="error">{{ error }}</p>
    <div class="card table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th><th>时间</th><th>源</th><th>目标</th><th>协议</th><th>方向</th><th>动作</th><th>规则</th><th>长度</th><th>原因</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="log in logs" :key="log.id">
            <td>{{ log.id }}</td>
            <td>{{ log.timestamp }}</td>
            <td>{{ log.src_ip }}:{{ log.src_port }}</td>
            <td>{{ log.dst_ip }}:{{ log.dst_port }}</td>
            <td>{{ log.protocol }}</td>
            <td>{{ log.direction }}</td>
            <td>{{ log.action }}</td>
            <td>{{ log.rule_id || '-' }}</td>
            <td>{{ log.packet_len }}</td>
            <td>{{ log.reason || '-' }}</td>
          </tr>
          <tr v-if="logs.length === 0">
            <td colspan="10">暂无日志</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import api, { errorMessage } from '../api/client'

const logs = ref([])
const error = ref('')

async function loadLogs() {
  try {
    const { data } = await api.get('/logs')
    logs.value = data.items || []
  } catch (err) {
    error.value = errorMessage(err, '日志加载失败')
  }
}

onMounted(loadLogs)
</script>
