# CWH 下载站 v2 - 企业级文件管理系统

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![MySQL Version](https://img.shields.io/badge/mysql-%3E%3D8.0-blue)](https://www.mysql.com/)

一个功能完整的企业级文件管理系统，支持私人空间、文件加密、角色权限、统计分析等功能。

## ✨ 核心特性

### 🔐 安全特性
- **文件加密** - AES-256-CBC 加密存储，每个文件独立 IV
- **角色权限** - 管理员和普通用户，细粒度权限控制
- **存储配额** - 每个用户默认 3GB，管理员可调整
- **访客追踪** - 记录所有访客，5 分钟内活跃算在线
- **下载日志** - 记录每次下载的用户、IP、时间

### 📁 文件管理
- **私人空间** - 加密存储，只有所有者可访问
- **公共空间** - 分享文件，支持密码保护
- **文件转存** - 引用机制，不占额外空间
- **分享链接** - 灵活的过期时间（1 月/1 年/永久/自定义）
- **失效提示** - 公共文件删除后，私人引用显示失效状态

### 👥 用户系统
- **个人资料** - 用户名、简介、头像
- **密码修改** - 需验证旧密码
- **角色管理** - 管理员可分配角色和调整配额
- **存储统计** - 实时显示存储使用情况

### 📊 统计分析
- **实时在线** - 包括未登录访客
- **下载排行** - 文件下载 Top 10
- **上传排行** - 用户上传 Top 10
- **流量趋势** - 最近 7 天下载趋势
- **文件属性** - 下载次数、排名、上传者

## 🚀 快速开始

### 环境要求

- Node.js >= 18.0.0
- MySQL >= 8.0
- npm 或 yarn

### 1. 克隆项目

```bash
git clone https://github.com/Pisces-Moze/CWH-dowloadstation.git
cd CWH-dowloadstation
git checkout v2-refactor
```

### 2. 安装依赖

```bash
cd backend
npm install
```

### 3. 配置数据库

创建 MySQL 数据库：

```sql
CREATE DATABASE cwh_download CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 4. 配置环境变量

创建 `backend/.env` 文件：

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

# CORS 配置（可选）
CORS_ORIGIN=http://localhost:5173
```

**生成安全的 JWT 密钥：**

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### 5. 启动服务

```bash
npm run dev
```

首次启动时会自动：
- 创建所有数据库表
- 创建默认管理员账户
- 在控制台显示管理员密码

**⚠️ 重要：请立即登录并修改默认管理员密码！**

### 6. 访问系统

- 后端 API: http://localhost:3000
- 管理员账户: `admin`
- 密码: 控制台显示的随机密码

## 📦 项目结构

```
backend/
├── src/
│   ├── config/
│   │   └── database.js          # 数据库配置和初始化
│   ├── middleware/
│   │   ├── auth.js              # JWT 认证中间件
│   │   ├── permission.js        # 权限验证中间件
│   │   └── errorHandler.js      # 错误处理中间件
│   ├── routes/
│   │   ├── auth.js              # 认证路由（注册/登录）
│   │   ├── files.js             # 文件路由（上传/下载/分享）
│   │   ├── admin.js             # 管理员路由（统计/用户管理）
│   │   └── profile.js           # 个人资料路由
│   ├── utils/
│   │   └── encryption.js        # 文件加密工具
│   └── server.js                # 服务器入口
├── uploads/                      # 文件存储目录（自动创建）
├── .env                          # 环境变量配置
├── .env.example                  # 环境变量示例
└── package.json
```

## 🔧 开发指南

### 可用脚本

```bash
# 开发模式（热重载）
npm run dev

# 生产模式
npm start

# 代码检查
npm run lint
```

### 数据库表结构

系统会自动创建以下表：

- `roles` - 角色表（管理员/普通用户）
- `users` - 用户表（扩展：角色、头像、简介、存储使用量）
- `files` - 文件表（加密 IV、MD5、私人标记）
- `file_references` - 文件引用表（转存功能）
- `share_links` - 分享链接表
- `visitor_sessions` - 访客会话表
- `download_logs` - 下载日志表

## 📖 API 文档

详细的 API 文档请查看：

- [私人空间功能文档](./PRIVATE_SPACE_FEATURE.md)
- [管理员和用户系统文档](./ADMIN_USER_SYSTEM.md)

### 快速参考

#### 认证接口

```bash
# 注册
POST /api/auth/register
Content-Type: application/json
{
  "username": "user123",
  "email": "user@example.com",
  "password": "password123"
}

# 登录
POST /api/auth/login
Content-Type: application/json
{
  "email": "user@example.com",
  "password": "password123"
}
```

#### 文件接口

```bash
# 上传文件
POST /api/files/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data
{
  "file": <file>,
  "isPrivate": true
}

# 下载文件
GET /api/files/download/:filename

# 创建分享链接
POST /api/files/share/:fileId
Authorization: Bearer <token>
Content-Type: application/json
{
  "expireType": "1month",
  "password": "123456",
  "maxDownloads": 100
}
```

#### 管理员接口

```bash
# 获取统计数据
GET /api/admin/stats
Authorization: Bearer <token>

# 获取用户列表
GET /api/admin/users
Authorization: Bearer <token>

# 更新用户角色
PUT /api/admin/users/:userId/role
Authorization: Bearer <token>
Content-Type: application/json
{
  "roleId": 1
}
```

## 🚢 生产部署

### 1. 构建前端（如果有）

```bash
cd frontend
npm run build
```

### 2. 配置生产环境

修改 `.env` 文件：

```env
NODE_ENV=production
PORT=3000
DB_HOST=your_production_db_host
# ... 其他生产配置
```

### 3. 使用 PM2 部署

```bash
# 安装 PM2
npm install -g pm2

# 启动服务
pm2 start src/server.js --name cwh-download

# 查看日志
pm2 logs cwh-download

# 设置开机自启
pm2 startup
pm2 save
```

### 4. 使用 Nginx 反向代理

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

### 5. 配置 HTTPS（推荐）

```bash
# 使用 Certbot 获取免费 SSL 证书
sudo certbot --nginx -d your-domain.com
```

## 🔒 安全建议

1. **修改默认密码** - 首次启动后立即修改管理员密码
2. **使用强密钥** - JWT_SECRET 使用 64 字节随机密钥
3. **启用 HTTPS** - 生产环境必须使用 HTTPS
4. **定期备份** - 定期备份数据库和上传文件
5. **更新依赖** - 定期更新 npm 依赖包
6. **限制访问** - 使用防火墙限制数据库访问
7. **日志监控** - 定期检查访问日志和错误日志

## 🐛 故障排除

### 数据库连接失败

```bash
# 检查 MySQL 服务是否运行
sudo systemctl status mysql

# 检查数据库配置
mysql -u root -p
SHOW DATABASES;
```

### 文件上传失败

```bash
# 检查上传目录权限
ls -la backend/uploads

# 修复权限
chmod 755 backend/uploads
```

### JWT 验证失败

- 检查 `.env` 中的 `JWT_SECRET` 是否正确
- 检查 token 是否过期
- 检查请求头格式：`Authorization: Bearer <token>`

## 📝 更新日志

### v2.0.0 (2026-04-18)

- ✨ 完整重构，模块化架构
- 🔐 文件加密存储（AES-256-CBC）
- 👥 角色权限系统
- 📊 统计仪表盘
- 💾 存储配额管理
- 🔗 文件分享功能
- 📱 个人资料系统
- 🚀 性能优化

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- [Node.js](https://nodejs.org/)
- [Express](https://expressjs.com/)
- [MySQL](https://www.mysql.com/)
- [JWT](https://jwt.io/)

## 📧 联系方式

- 作者：沫然 (MoRan) 🐱
- 博客：https://blog.pmoze.top
- GitHub：https://github.com/Pisces-Moze

---

**⭐ 如果这个项目对你有帮助，请给个 Star！**
