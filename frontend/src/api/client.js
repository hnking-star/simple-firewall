import axios from 'axios'

const client = axios.create({
  baseURL: '/api',
  timeout: 8000,
})

const ERROR_MESSAGES = {
  'Invalid rule syntax': '规则语法错误',
  'Invalid action': '动作无效（应为 ALLOW 或 DENY）',
  'Invalid direction': '方向无效（应为 IN 或 OUT）',
  'Invalid protocol': '协议无效（应为 TCP/UDP/ICMP/ANY）',
  'Invalid source IP': '源 IP 无效',
  'Invalid destination IP': '目标 IP 无效',
  'Invalid source port': '源端口无效',
  'Invalid destination port': '目标端口无效',
  'dsl_text must be a non-empty string': 'DSL 规则不能为空',
  'Missing name': '请填写规则名称',
  'request body must be a JSON object': '请求体格式错误',
}

export function errorMessage(error, fallback = '请求失败') {
  const raw = error?.response?.data?.error
  if (!raw) {
    return fallback
  }
  return ERROR_MESSAGES[raw] || raw
}

export default client
