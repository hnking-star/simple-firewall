<template>
  <section>
    <h2 class="page-title">规则管理</h2>

    <div class="card">
      <label>规则名称</label>
      <input v-model="form.name" placeholder="例如：block dns" />
      <label>DSL</label>
      <textarea v-model="form.dsl_text"></textarea>
      <div class="grid form-grid">
        <label>
          是否启用
          <select v-model="form.enabled">
            <option :value="true">启用</option>
            <option :value="false">禁用</option>
          </select>
        </label>
        <label>
          优先级
          <input v-model.number="form.priority" type="number" min="1" />
        </label>
      </div>
      <div class="actions">
        <button @click="parseRule">解析</button>
        <button @click="saveRule">{{ editingId ? '更新' : '保存' }}</button>
        <button v-if="editingId" class="secondary" @click="resetForm">取消编辑</button>
        <button class="secondary" @click="applyRules">应用规则（dry-run）</button>
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
            <th>ID</th><th>名称</th><th>动作</th><th>方向</th><th>协议</th><th>源</th><th>目标</th><th>端口</th><th>启用</th><th>优先级</th><th>操作</th>
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
            <td>
              <div class="row-actions">
                <button @click="editRule(rule)">编辑</button>
                <button class="secondary" @click="toggleRule(rule)">{{ rule.enabled ? '禁用' : '启用' }}</button>
                <button class="danger" @click="deleteRule(rule)">删除</button>
              </div>
            </td>
          </tr>
          <tr v-if="rules.length === 0">
            <td colspan="11">暂无规则</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import api, { errorMessage } from '../api/client'

const defaultForm = {
  name: 'block dns',
  dsl_text: 'DENY OUT UDP FROM ANY TO 8.8.8.8 SPORT ANY DPORT 53',
  enabled: true,
  priority: 100,
}

const form = ref({ ...defaultForm })
const editingId = ref(null)
const parsed = ref(null)
const rules = ref([])
const message = ref('')
const error = ref('')

function clearNotice() {
  message.value = ''
  error.value = ''
}

function rulePayload(rule = form.value) {
  return {
    name: rule.name,
    dsl_text: rule.dsl_text,
    enabled: Boolean(rule.enabled),
    priority: Number(rule.priority) || 100,
  }
}

function resetForm() {
  form.value = { ...defaultForm }
  editingId.value = null
  parsed.value = null
  clearNotice()
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
    const { data } = await api.post('/rules/parse', { dsl_text: form.value.dsl_text })
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
    if (editingId.value) {
      await api.put(`/rules/${editingId.value}`, rulePayload())
      message.value = '更新成功'
    } else {
      await api.post('/rules', rulePayload())
      message.value = '保存成功'
    }
    await loadRules()
  } catch (err) {
    error.value = errorMessage(err, '保存失败')
  }
}

function editRule(rule) {
  form.value = rulePayload(rule)
  editingId.value = rule.id
  parsed.value = null
  clearNotice()
}

async function deleteRule(rule) {
  clearNotice()
  try {
    await api.delete(`/rules/${rule.id}`)
    if (editingId.value === rule.id) {
      resetForm()
    }
    message.value = '删除成功'
    await loadRules()
  } catch (err) {
    error.value = errorMessage(err, '删除失败')
  }
}

async function toggleRule(rule) {
  clearNotice()
  try {
    await api.put(`/rules/${rule.id}`, {
      ...rulePayload(rule),
      enabled: !rule.enabled,
    })
    message.value = rule.enabled ? '已禁用' : '已启用'
    await loadRules()
  } catch (err) {
    error.value = errorMessage(err, '操作失败')
  }
}

async function applyRules() {
  clearNotice()
  try {
    const { data } = await api.post('/rules/apply', { dry_run: true })
    message.value = `dry-run 完成，生成命令 ${data.applied_count || 0} 条`
  } catch (err) {
    error.value = errorMessage(err, '应用规则失败')
  }
}

onMounted(loadRules)
</script>
