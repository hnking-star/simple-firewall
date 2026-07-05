import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from './pages/Dashboard.vue'
import Login from './pages/Login.vue'
import Logs from './pages/Logs.vue'
import Monitor from './pages/Monitor.vue'
import Rules from './pages/Rules.vue'
import Settings from './pages/Settings.vue'

const routes = [
  { path: '/login', component: Login, meta: { public: true } },
  { path: '/', component: Dashboard },
  { path: '/rules', component: Rules },
  { path: '/monitor', component: Monitor },
  { path: '/logs', component: Logs },
  { path: '/settings', component: Settings },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const loggedIn = localStorage.getItem('simple_firewall_logged_in') === '1'
  if (!to.meta.public && !loggedIn) {
    return '/login'
  }
  if (to.path === '/login' && loggedIn) {
    return '/'
  }
  return true
})

export default router
