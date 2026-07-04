<template>
  <div class="layout">
    <aside class="sidebar">
      <h1>防火墙管理</h1>
      <nav>
        <RouterLink to="/">首页概览</RouterLink>
        <RouterLink to="/rules">规则管理</RouterLink>
        <RouterLink to="/monitor">抓包监控</RouterLink>
        <RouterLink to="/logs">日志审计</RouterLink>
        <RouterLink to="/settings">系统设置</RouterLink>
      </nav>
    </aside>
    <main class="content">
      <RouterView />
    </main>
  </div>
</template>
