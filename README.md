# 简易防火墙管理系统

本项目使用 Vue3、Flask、SQLite、Scapy 和 iptables 实现一个简易的 Linux 防火墙管理系统，支持规则配置、自定义规则语言解析、流量监控、日志审计和运行结果图表展示。

## 目录结构

```
backend/    Flask 后端：REST API、DSL 解析器、iptables 适配器、Scapy 抓包、SQLite 存储
frontend/   Vue3 前端：首页概览、规则管理、抓包监控、日志审计、系统设置
docs/       课程文档：功能目标分解表、规则语言说明、课程设计报告
```

## 后端运行

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

后端默认监听 `http://127.0.0.1:5000`，`GET /api/health` 返回 `{"status":"ok"}`。

## 前端运行

```bash
cd frontend
npm install
npm run dev
```

前端默认监听 `http://127.0.0.1:5173`，通过 Vite 代理访问后端 `/api`。

## 后端测试

```bash
cd backend
pytest -v
```

## Linux 真实拦截说明

应用 iptables 规则和 Scapy 抓包需要 root 或 sudo 权限。默认开发/测试路径使用 dry-run，不会真正修改主机防火墙。建议在虚拟机中运行真实拦截测试，避免影响本机网络。

真实拦截验证示例：

```bash
# 前端新增一条出站 DNS 拦截规则后，系统会生成如下命令
iptables -A OUTPUT -p udp -d 8.8.8.8 --dport 53 -j DROP

# 规则生效时 DNS 查询失败，删除规则后恢复
dig @8.8.8.8 example.com
```
