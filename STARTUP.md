# 启动指南

## 🚀 一键启动（推荐）

### 开发环境

```bash
cd backend
npm install
npm run dev:full
```

这会自动：
1. 构建前端（生成 dist/ 目录）
2. 启动后端服务器
3. 后端同时提供前端静态文件服务

**访问地址：** http://localhost:3000

### 生产环境

```bash
cd backend
npm install
npm run start:full
```

## 📦 分离启动（开发调试）

如果需要前端热重载，可以分别启动：

### 终端 1 - 后端

```bash
cd backend
npm install
cp .env.example .env
# 编辑 .env 配置数据库
npm run dev
```

### 终端 2 - 前端

```bash
# 在项目根目录
npm install
npm run dev
```

**访问地址：**
- 前端：http://localhost:5173
- 后端：http://localhost:3000

## ⚙️ 配置

### 后端配置 (backend/.env)

```env
# 数据库配置
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=cwh_download

# JWT 配置
JWT_SECRET=your_jwt_secret_key_here
JWT_EXPIRES_IN=7d

# 服务器配置
PORT=3000
NODE_ENV=development

# 文件上传配置
UPLOAD_DIR=./uploads
MAX_FILE_SIZE=104857600
```

### 前端配置 (.env)

```env
VITE_API_BASE_URL=http://localhost:3000/api
```

## 🎯 启动流程

### Windows (PowerShell)

```powershell
# 一键启动
cd E:\desktop\CWH-dowloadstation\backend
npm install
npm run dev:full
```

### Linux / macOS

```bash
# 一键启动
cd ~/CWH-dowloadstation/backend
npm install
npm run dev:full
```

## 📝 首次启动

1. **配置数据库**
   - 创建 MySQL 数据库
   - 编辑 `backend/.env` 配置数据库连接

2. **启动服务**
   ```bash
   cd backend
   npm run dev:full
   ```

3. **获取管理员密码**
   - 首次启动会在控制台显示管理员密码
   - 用户名：`admin`
   - 密码：控制台显示的随机密码

4. **访问系统**
   - 打开浏览器访问 http://localhost:3000
   - 使用管理员账户登录

## 🔧 可用命令

### 后端命令

```bash
cd backend

# 开发模式（仅后端）
npm run dev

# 开发模式（前端+后端）
npm run dev:full

# 生产模式（仅后端）
npm start

# 生产模式（前端+后端）
npm run start:full

# 仅构建前端
npm run build:frontend
```

### 前端命令（项目根目录）

```bash
# 开发模式（热重载）
npm run dev

# 构建生产版本
npm run build

# 预览构建结果
npm run preview
```

## 🌐 访问地址

### 一键启动模式
- **所有功能：** http://localhost:3000

### 分离启动模式
- **前端界面：** http://localhost:5173
- **后端 API：** http://localhost:3000/api

## ❓ 常见问题

### 1. 前端无法访问

**问题：** 访问 http://localhost:3000 显示 404

**解决：**
```bash
cd backend
npm run build:frontend
npm run dev
```

### 2. 端口被占用

**修改后端端口：**
编辑 `backend/.env`：
```env
PORT=3001
```

**修改前端端口：**
编辑 `vite.config.js`：
```js
export default {
  server: {
    port: 5174
  }
}
```

### 3. 数据库连接失败

检查：
- MySQL 服务是否运行
- `backend/.env` 配置是否正确
- 数据库是否已创建

### 4. 前端构建失败

```bash
# 清理并重新安装依赖
rm -rf node_modules package-lock.json
npm install
npm run build
```

## 🚢 生产部署

### 使用 PM2

```bash
# 安装 PM2
npm install -g pm2

# 构建前端
cd backend
npm run build:frontend

# 启动服务
pm2 start src/server.js --name cwh-download

# 查看日志
pm2 logs cwh-download

# 设置开机自启
pm2 startup
pm2 save
```

### 使用 Docker

```bash
# 构建镜像
docker build -t cwh-download .

# 运行容器
docker run -d -p 3000:3000 --name cwh cwh-download
```

### 使用 Nginx 反向代理

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 📊 性能优化

### 生产环境建议

1. **启用 HTTPS**
   - 配置 SSL 证书
   - 设置 `NODE_ENV=production`

2. **使用 CDN**
   - 将静态资源部署到 CDN
   - 修改前端 API 地址

3. **数据库优化**
   - 添加索引
   - 定期清理日志表

4. **缓存策略**
   - 使用 Redis 缓存
   - 配置浏览器缓存

## 🎉 总结

**推荐启动方式：**

```bash
cd backend
npm run dev:full
```

一条命令，前后端全部搞定喵~
