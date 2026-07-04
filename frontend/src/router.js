import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from './pages/Dashboard.vue'
import Logs from './pages/Logs.vue'
import Monitor from './pages/Monitor.vue'
import Rules from './pages/Rules.vue'
import Settings from './pages/Settings.vue'

const routes = [
  { path: '/', component: Dashboard },
  { path: '/rules', component: Rules },
  { path: '/monitor', component: Monitor },
  { path: '/logs', component: Logs },
  { path: '/settings', component: Settings },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
