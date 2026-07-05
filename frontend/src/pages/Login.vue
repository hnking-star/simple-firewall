<template>
  <section class="login-page">
    <div class="login-card">
      <h2>简易防火墙系统</h2>
      <p class="login-subtitle">请输入账号密码登录管理后台</p>
      <label>
        账号
        <input v-model="username" placeholder="admin" @keyup.enter="login" />
      </label>
      <label>
        密码
        <input v-model="password" type="password" placeholder="请输入密码" @keyup.enter="login" />
      </label>
      <button class="login-button" @click="login">登录</button>
      <p v-if="error" class="error">{{ error }}</p>
    </div>
  </section>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const username = ref('admin')
const password = ref('')
const error = ref('')

function login() {
  error.value = ''
  if (username.value === 'admin' && password.value === 'fly200411') {
    localStorage.setItem('simple_firewall_logged_in', '1')
    router.push('/')
    return
  }
  error.value = '账号或密码错误'
}
</script>
