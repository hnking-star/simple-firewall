import axios from 'axios'

const client = axios.create({
  baseURL: '/api',
  timeout: 8000,
})

export function errorMessage(error, fallback = '请求失败') {
  return error?.response?.data?.error || fallback
}

export default client
