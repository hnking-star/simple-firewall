<template>
  <RouterView v-if="isLoginPage" />
  <div v-else class="layout">
    <aside class="sidebar">
      <h1>防火墙管理</h1>
      <nav>
        <RouterLink to="/">首页概览</RouterLink>
        <RouterLink to="/rules">规则管理</RouterLink>
        <RouterLink to="/monitor">抓包监控</RouterLink>
        <RouterLink to="/logs">操作记录</RouterLink>
        <RouterLink to="/settings">系统设置</RouterLink>
      </nav>
      <button class="logout-button" @click="logout">退出登录</button>
    </aside>
    <main class="content">
      <RouterView />
    </main>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()
const isLoginPage = computed(() => route.path === '/login')

function logout() {
  localStorage.removeItem('simple_firewall_logged_in')
  router.push('/login')
}
</script>
