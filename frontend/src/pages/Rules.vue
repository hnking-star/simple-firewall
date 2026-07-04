<template>
  <section>
    <h2 class="page-title">规则管理</h2>

    <div class="card">
      <label>规则名称</label>
      <input v-model="name" placeholder="例如：block dns" />
      <label>DSL</label>
      <textarea v-model="dslText"></textarea>
      <div class="actions">
        <button @click="parseRule">解析</button>
        <button @click="saveRule">保存</button>
        <span v-if="message" class="message">{{ message }}</span>
        <span v-if="error" class="error">{{ error }}</span>
      </div>
      <pre v-if="parsed">{{ parsed }}</pre>
    </div>

    <div class="card table-wrap">
      <h3>规则列表</h3>
      <table>
        <thead>
          <tr>
            <th>ID</th><th>名称</th><th>动作</th><th>方向</th><th>协议</th><th>源</th><th>目标</th><th>端口</th><th>启用</th><th>优先级</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="rule in rules" :key="rule.id">
            <td>{{ rule.id }}</td>
            <td>{{ rule.name }}</td>
            <td>{{ rule.action }}</td>
            <td>{{ rule.direction }}</td>
            <td>{{ rule.protocol }}</td>
            <td>{{ rule.src_ip }}:{{ rule.src_port }}</td>
            <td>{{ rule.dst_ip }}</td>
            <td>{{ rule.dst_port }}</td>
            <td>{{ rule.enabled ? '是' : '否' }}</td>
            <td>{{ rule.priority }}</td>
          </tr>
          <tr v-if="rules.length === 0">
            <td colspan="10">暂无规则</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import api, { errorMessage } from '../api/client'

const defaultDsl = 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53'
const dslText = ref(defaultDsl)
const name = ref('block dns')
const parsed = ref(null)
const rules = ref([])
const message = ref('')
const error = ref('')

function clearNotice() {
  message.value = ''
  error.value = ''
}

async function loadRules() {
  try {
    const { data } = await api.get('/rules')
    rules.value = data.items || []
  } catch (err) {
    error.value = errorMessage(err, '规则加载失败')
  }
}

async function parseRule() {
  clearNotice()
  try {
    const { data } = await api.post('/rules/parse', { dsl_text: dslText.value })
    parsed.value = data
    message.value = '解析成功'
  } catch (err) {
    parsed.value = null
    error.value = errorMessage(err, '解析失败')
  }
}

async function saveRule() {
  clearNotice()
  try {
    await api.post('/rules', {
      name: name.value,
      dsl_text: dslText.value,
      enabled: true,
      priority: 100,
    })
    message.value = '保存成功'
    await loadRules()
  } catch (err) {
    error.value = errorMessage(err, '保存失败')
  }
}

onMounted(loadRules)
</script>
