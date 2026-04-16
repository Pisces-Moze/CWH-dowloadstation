# 智享云阁 CWH v2.0 🐧

一个现代化的公益文件分享平台，使用 Vue 3 + Vite + Express 重构。

## ✨ 特性

- 🎨 现代化 UI 设计（Naive UI）
- 📱 响应式布局，支持移动端
- 🔐 安全的用户认证（JWT）
- 📤 拖拽上传，支持批量上传
- 📊 文件管理和统计
- ⚡ 快速的开发体验（Vite HMR）
- 🛡️ 安全加固（Helmet、输入验证）

## 🚀 技术栈

### 前端
- Vue 3 - 渐进式 JavaScript 框架
- Vite - 下一代前端构建工具
- Vue Router - 官方路由
- Pinia - 状态管理
- Naive UI - Vue 3 组件库
- Axios - HTTP 客户端

### 后端
- Node.js + Express - Web 框架
- MySQL - 数据库
- JWT - 身份认证
- Multer - 文件上传
- Bcrypt - 密码加密

## 📦 安装

### 前端

\`\`\`bash
cd CWH-v2
npm install
npm run dev
\`\`\`

### 后端

\`\`\`bash
cd CWH-v2/backend
npm install

# 复制环境变量配置
cp .env.example .env
# 编辑 .env 文件，配置数据库等信息

npm run dev
\`\`\`

## ⚙️ 配置

### 数据库

1. 创建 MySQL 数据库：
\`\`\`sql
CREATE DATABASE users CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
\`\`\`

2. 修改 `backend/.env` 文件中的数据库配置：
\`\`\`env
DB_HOST=127.0.0.1
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=users
\`\`\`

3. 启动后端服务，数据库表会自动创建

### JWT 密钥

生成安全的 JWT 密钥：
\`\`\`bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
\`\`\`

将生成的密钥填入 `backend/.env` 的 `JWT_SECRET`

## 🏗️ 项目结构

\`\`\`
CWH-v2/
├── src/                    # 前端源码
│   ├── api/               # API 请求
│   ├── assets/            # 静态资源
│   ├── components/        # 组件
│   ├── router/            # 路由
│   ├── stores/            # 状态管理
│   ├── views/             # 页面
│   ├── App.vue           # 根组件
│   └── main.js           # 入口文件
├── backend/               # 后端源码
│   └── src/
│       ├── config/        # 配置
│       ├── middleware/    # 中间件
│       ├── routes/        # 路由
│       └── server.js      # 服务器入口
├── public/                # 公共资源
├── index.html            # HTML 模板
├── vite.config.js        # Vite 配置
└── package.json          # 依赖配置
\`\`\`

## 🔒 安全改进

相比旧版本，v2.0 做了以下安全改进：

- ✅ 环境变量配置（不再硬编码密码）
- ✅ Helmet 安全头
- ✅ 输入验证（express-validator）
- ✅ SQL 注入防护（参数化查询）
- ✅ XSS 防护
- ✅ CORS 配置
- ✅ JWT 过期时间
- ✅ 密码加密（bcrypt）

## 📝 API 文档

### 认证

- `POST /api/auth/signup` - 注册
- `POST /api/auth/login` - 登录

### 文件

- `GET /api/files` - 获取文件列表
- `GET /api/my-files` - 获取我的文件（需认证）
- `POST /api/upload` - 上传文件（需认证）
- `GET /api/download/:filename` - 下载文件
- `DELETE /api/files/:id` - 删除文件（需认证）

## 🚢 部署

### 生产环境构建

前端：
\`\`\`bash
npm run build
\`\`\`

后端：
\`\`\`bash
cd backend
npm start
\`\`\`

### 使用 HTTPS

1. 将 SSL 证书放到 `backend/key/` 目录
2. 在 `.env` 中配置证书路径
3. 设置 `NODE_ENV=production`

## 📄 许可证

MIT License

## 🙏 致谢

- Vue.js 团队
- Naive UI 团队
- Express.js 团队

---

**重构完成时间：** 2026-04-17  
**重构者：** 沫然 (MoRan) 🐱
