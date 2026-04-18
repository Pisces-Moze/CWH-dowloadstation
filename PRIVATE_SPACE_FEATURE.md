# 私人空间与文件加密功能

## 新增功能

### 1. 私人空间
- 每个用户拥有独立的私人文件空间
- 私人文件只有上传者本人可见和下载
- 严格的权限验证，防止未授权访问

### 2. 文件加密
- 所有文件（公共+私人）使用 AES-256-CBC 加密存储
- 每个文件独立的 IV（初始化向量）
- 下载时自动解密，对用户透明

### 3. 分享功能
- 公共文件支持生成分享链接
- 支持设置分享密码
- 支持设置过期时间
- 支持限制下载次数
- 一键复制分享链接

### 4. 安全增强
- 私人文件绝对隔离，无法通过任何方式访问他人文件
- 分享链接带有随机 32 位十六进制码
- 过期和次数限制自动失效

## API 接口

### 上传文件
```
POST /api/files/upload
Headers: Authorization: Bearer <token>
Body: multipart/form-data
  - file: 文件
  - isPrivate: true/false (是否私人空间)
```

### 获取公共文件列表
```
GET /api/files/files
无需认证
```

### 获取我的私人文件
```
GET /api/files/private-files
Headers: Authorization: Bearer <token>
```

### 获取我的公共文件
```
GET /api/files/my-files
Headers: Authorization: Bearer <token>
```

### 下载文件
```
GET /api/files/download/:filename
Headers: Authorization: Bearer <token> (私人文件必需)
```

### 创建分享链接
```
POST /api/files/share/:fileId
Headers: Authorization: Bearer <token>
Body: {
  "password": "可选密码",
  "expiresIn": 24, // 小时数，可选
  "maxDownloads": 10 // 最大下载次数，可选
}

Response: {
  "success": true,
  "shareUrl": "https://xxx/api/files/s/abc123...",
  "shareCode": "abc123...",
  "expiresAt": "2026-04-19T12:00:00.000Z"
}
```

### 通过分享链接下载
```
GET /api/files/s/:shareCode?password=xxx
无需认证
```

### 删除文件
```
DELETE /api/files/files/:id
Headers: Authorization: Bearer <token>
```

### 删除分享链接
```
DELETE /api/files/share/:shareCode
Headers: Authorization: Bearer <token>
```

## 数据库变更

### files 表新增字段
- `is_private` BOOLEAN - 是否私人文件
- `encryption_iv` VARCHAR(32) - 加密 IV

### 新增 share_links 表
- `id` - 主键
- `file_id` - 文件 ID
- `share_code` - 分享码（32位十六进制）
- `password` - 分享密码（可选）
- `expires_at` - 过期时间（可选）
- `downloads` - 已下载次数
- `max_downloads` - 最大下载次数（0=无限制）
- `created_at` - 创建时间

## 环境变量配置

需要在 `.env` 中添加：
```
ENCRYPTION_KEY=<64位十六进制字符串>
```

如果不设置，系统会自动生成（但重启后会变，导致旧文件无法解密）

生成密钥：
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 安全特性

1. **文件加密**
   - AES-256-CBC 算法
   - 每个文件独立 IV
   - 密钥存储在环境变量

2. **访问控制**
   - 私人文件：必须是文件所有者
   - 公共文件：任何人可下载
   - 分享链接：验证密码、过期时间、下载次数

3. **防止未授权访问**
   - JWT 令牌验证
   - 数据库级别的用户 ID 检查
   - 文件系统隔离

## 前端集成建议

### 上传界面
- 添加"上传到私人空间"复选框
- 上传时传递 `isPrivate` 参数

### 文件列表
- 分为"公共空间"和"私人空间"两个标签页
- 私人空间显示锁图标

### 分享功能
- 在文件列表添加"分享"按钮（仅公共文件）
- 弹窗设置分享选项（密码、过期时间、下载次数）
- 显示分享链接，提供一键复制按钮

### 示例代码
```javascript
// 上传到私人空间
const formData = new FormData()
formData.append('file', file)
formData.append('isPrivate', 'true')

await axios.post('/api/files/upload', formData, {
  headers: { Authorization: `Bearer ${token}` }
})

// 创建分享链接
const { data } = await axios.post(`/api/files/share/${fileId}`, {
  password: '123456',
  expiresIn: 24,
  maxDownloads: 10
}, {
  headers: { Authorization: `Bearer ${token}` }
})

// 复制分享链接
navigator.clipboard.writeText(data.shareUrl)
```

## 测试建议

1. 上传私人文件，尝试用其他账号访问（应失败）
2. 上传公共文件，创建分享链接
3. 测试分享密码验证
4. 测试过期时间
5. 测试下载次数限制
6. 测试文件加密解密（下载后验证文件完整性）

---

**实现时间：** 2026-04-18  
**实现者：** 沫然
