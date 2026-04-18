# 启动指南

## 前端启动

### 1. 安装依赖

```bash
# 在项目根目录
npm install
```

### 2. 配置环境变量

创建 `.env` 文件（可选，默认连接本地后端）：

```bash
# 复制示例文件
cp .env.example .env
```

`.env` 内容：
```env
VITE_API_BASE_URL=http://localhost:3000/api
```

### 3. 启动开发服务器

```bash
npm run dev
```

前端会在 **http://localhost:5173** 启动

## 后端启动

```bash
cd backend
npm install
cp .env.example .env
# 编辑 .env 配置数据库
npm run dev
```

后端会在 **http://localhost:3000** 启动

## 完整启动流程

### Windows (PowerShell)

```powershell
# 终端 1 - 启动后端
cd E:\desktop\CWH-dowloadstation\backend
npm install
npm run dev

# 终端 2 - 启动前端
cd E:\desktop\CWH-dowloadstation
npm install
npm run dev
```

### 访问地址

- **前端界面：** http://localhost:5173
- **后端 API：** http://localhost:3000/api

## 注意事项

1. **必须先启动后端**，前端才能正常工作
2. **首次启动**后端会自动创建数据库表和管理员账户
3. **管理员密码**会在后端控制台显示，请记录下来
4. 前端和后端需要**同时运行**

## 常见问题

### 前端无法连接后端

检查：
- 后端是否正常运行（http://localhost:3000）
- `.env` 中的 `VITE_API_BASE_URL` 是否正确
- 浏览器控制台是否有 CORS 错误

### 端口被占用

修改端口：
- 前端：编辑 `vite.config.js`，添加 `server: { port: 5174 }`
- 后端：编辑 `backend/.env`，修改 `PORT=3001`

## 生产部署

### 构建前端

```bash
npm run build
```

生成的 `dist/` 目录可以部署到任何静态服务器（Nginx、Apache、Vercel 等）

### 启动后端

```bash
cd backend
npm start
```

建议使用 PM2 进行进程管理：

```bash
pm2 start backend/src/server.js --name cwh-backend
```
