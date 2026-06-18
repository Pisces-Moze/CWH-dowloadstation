# 管理员和用户系统功能文档

## 功能概述

### 1. 角色系统
- **管理员角色** - 拥有完整管理权限
- **普通用户角色** - 基础文件上传下载权限

### 2. 权限分工
| 权限 | 管理员 | 普通用户 |
|------|--------|----------|
| 删除公共文件 | ✅ | ❌ |
| 管理用户 | ✅ | ❌ |
| 查看统计数据 | ✅ | ❌ |
| 上传文件 | ✅ | ✅ |
| 私人空间 | 3GB | 3GB |

### 3. 初始化
首次启动时自动创建管理员账户：
- 用户名：`admin`
- 密码：随机生成（控制台显示）
- ⚠️ 请立即登录并修改密码！

## API 接口

### 管理员接口

#### 获取统计数据
```
GET /api/admin/stats
Headers: Authorization: Bearer <token>

Response: {
  "success": true,
  "stats": {
    "totalUsers": 100,
    "totalFiles": 500,
    "totalSize": 1073741824,
    "totalDownloads": 1000,
    "onlineUsers": 5,
    "topFiles": [...],
    "topUploaders": [...],
    "downloadTrend": [...]
  }
}
```

#### 获取用户列表
```
GET /api/admin/users
Headers: Authorization: Bearer <token>

Response: {
  "success": true,
  "users": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@localhost",
      "storage_used": 0,
      "storage_quota": 3221225472,
      "role_name": "admin",
      "role_display_name": "管理员",
      "created_at": "2026-04-18T00:00:00.000Z"
    }
  ]
}
```

#### 更新用户角色
```
PUT /api/admin/users/:userId/role
Headers: Authorization: Bearer <token>
Body: {
  "roleId": 1
}

Response: {
  "success": true,
  "message": "角色已更新"
}
```

#### 更新用户存储配额
```
PUT /api/admin/users/:userId/quota
Headers: Authorization: Bearer <token>
Body: {
  "quota": 5368709120
}

Response: {
  "success": true,
  "message": "存储配额已更新"
}
```

#### 删除用户
```
DELETE /api/admin/users/:userId
Headers: Authorization: Bearer <token>

Response: {
  "success": true,
  "message": "用户已删除"
}
```

#### 获取角色列表
```
GET /api/admin/roles
Headers: Authorization: Bearer <token>

Response: {
  "success": true,
  "roles": [
    {
      "id": 1,
      "name": "admin",
      "display_name": "管理员",
      "storage_quota": 3221225472,
      "can_delete_public_files": true,
      "can_manage_users": true,
      "can_view_stats": true
    }
  ]
}
```

### 用户个人资料接口

#### 获取当前用户资料
```
GET /api/profile/me
Headers: Authorization: Bearer <token>

Response: {
  "success": true,
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@localhost",
    "bio": "个人简介",
    "storageUsed": 0,
    "storageQuota": 3221225472,
    "avatarUrl": "/api/files/download/avatar_1_xxx.jpg",
    "role": {
      "id": 1,
      "name": "admin",
      "displayName": "管理员"
    },
    "createdAt": "2026-04-18T00:00:00.000Z"
  }
}
```

#### 获取其他用户公开资料
```
GET /api/profile/:userId

Response: {
  "success": true,
  "user": {
    "id": 2,
    "username": "user123",
    "bio": "个人简介",
    "avatarUrl": "/api/files/download/avatar_2_xxx.jpg",
    "role": "普通用户",
    "publicFileCount": 10,
    "totalDownloads": 100,
    "createdAt": "2026-04-18T00:00:00.000Z"
  }
}
```

#### 更新用户资料
```
PUT /api/profile/me
Headers: Authorization: Bearer <token>
Body: {
  "username": "newname",
  "bio": "新的个人简介"
}

Response: {
  "success": true,
  "message": "资料已更新"
}
```

#### 修改密码
```
PUT /api/profile/me/password
Headers: Authorization: Bearer <token>
Body: {
  "oldPassword": "oldpass",
  "newPassword": "newpass"
}

Response: {
  "success": true,
  "message": "密码已更新"
}
```

#### 上传头像
```
POST /api/profile/me/avatar
Headers: Authorization: Bearer <token>
Content-Type: multipart/form-data
Body: FormData with 'avatar' field

Response: {
  "success": true,
  "message": "头像已更新",
  "avatarUrl": "/api/files/download/avatar_1_xxx.jpg"
}
```

### 文件详情增强

#### 获取文件详情（含排名）
```
GET /api/files/file-info/:fileId

Response: {
  "success": true,
  "file": {
    "name": "文件名.txt",
    "size": "1.5 MB",
    "sizeBytes": 1572864,
    "mimeType": "text/plain",
    "downloads": 42,
    "downloadRank": 5,
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "uploadTime": "2026-04-18T04:00:00.000Z",
    "uploader": "username",
    "uploaderUserId": 2,
    "isPrivate": false
  }
}
```

## 安全特性

### 1. 权限验证
- 所有管理接口都需要管理员权限
- 用户只能修改自己的资料
- 管理员不能删除自己或修改自己的角色

### 2. 存储配额
- 每个用户默认 3GB 私人空间
- 上传时自动检查配额
- 超出配额时拒绝上传

### 3. 访客追踪
- 自动记录所有访客（包括未登录用户）
- 5分钟内活跃算在线
- 记录 IP 和 User-Agent

### 4. 下载日志
- 记录每次下载的用户、IP、时间
- 用于统计和审计

### 5. 头像安全
- 头像存储在私人空间
- 只有所有者可以访问
- 自动删除旧头像

## 前端集成建议

### 管理员控制面板
```javascript
// 获取统计数据
const { data } = await axios.get('/api/admin/stats', {
  headers: { Authorization: `Bearer ${token}` }
})

// 显示仪表盘
<Dashboard>
  <StatCard title="总用户数" value={data.stats.totalUsers} />
  <StatCard title="在线人数" value={data.stats.onlineUsers} />
  <FileRankingTable data={data.stats.topFiles} />
  <UserRankingTable data={data.stats.topUploaders} />
  <DownloadTrendChart data={data.stats.downloadTrend} />
</Dashboard>
```

### 用户资料页面
```javascript
// 获取用户资料
const { data } = await axios.get(`/api/profile/${userId}`)

// 显示资料
<UserProfile>
  <Avatar src={data.user.avatarUrl} />
  <Username>{data.user.username}</Username>
  <Role>{data.user.role}</Role>
  <Bio>{data.user.bio}</Bio>
  <Stats>
    <Stat label="公开文件" value={data.user.publicFileCount} />
    <Stat label="总下载量" value={data.user.totalDownloads} />
  </Stats>
</UserProfile>
```

### 文件详情弹窗
```javascript
// 获取文件详情
const { data } = await axios.get(`/api/files/file-info/${fileId}`)

// 显示详情
<FileInfoModal>
  <InfoRow label="文件名" value={data.file.name} />
  <InfoRow label="大小" value={data.file.size} />
  <InfoRow label="下载次数" value={data.file.downloads} />
  <InfoRow label="排名" value={`第 ${data.file.downloadRank} 名`} />
  <InfoRow label="MD5" value={data.file.md5} />
  <InfoRow label="上传者">
    <Link to={`/profile/${data.file.uploaderUserId}`}>
      {data.file.uploader}
    </Link>
  </InfoRow>
</FileInfoModal>
```

## 数据库变更

### 新增表
- `roles` - 角色表
- `visitor_sessions` - 访客会话表
- `download_logs` - 下载日志表

### 修改表
- `users` - 添加 `role_id`, `avatar_file_id`, `bio`, `storage_used`
- `files` - 已有字段无变化

## 注意事项

1. **首次启动**：记录控制台显示的管理员密码
2. **安全性**：立即修改默认管理员密码
3. **配额管理**：定期检查用户存储使用情况
4. **日志清理**：定期清理旧的访客会话和下载日志
5. **头像限制**：头像大小限制 5MB，只支持图片格式
