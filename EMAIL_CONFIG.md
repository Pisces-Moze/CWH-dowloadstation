# 邮件配置指南

## 配置邮箱验证码功能

注册功能需要发送邮箱验证码，需要配置 SMTP 邮件服务。

### 1. Gmail 配置（推荐）

#### 步骤 1：启用两步验证
1. 访问 https://myaccount.google.com/security
2. 启用"两步验证"

#### 步骤 2：生成应用专用密码
1. 访问 https://myaccount.google.com/apppasswords
2. 选择"邮件"和"其他（自定义名称）"
3. 输入"CWH 下载站"
4. 点击"生成"
5. 复制生成的 16 位密码

#### 步骤 3：配置 .env
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_email@gmail.com
SMTP_PASS=生成的16位应用专用密码
SMTP_FROM_NAME=CWH 下载站
```

### 2. QQ 邮箱配置

#### 步骤 1：开启 SMTP 服务
1. 登录 QQ 邮箱
2. 设置 → 账户
3. 开启"POP3/SMTP服务"
4. 获取授权码

#### 步骤 2：配置 .env
```env
SMTP_HOST=smtp.qq.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_qq_number@qq.com
SMTP_PASS=授权码
SMTP_FROM_NAME=CWH 下载站
```

### 3. 163 邮箱配置

#### 步骤 1：开启 SMTP 服务
1. 登录 163 邮箱
2. 设置 → POP3/SMTP/IMAP
3. 开启"SMTP服务"
4. 获取授权密码

#### 步骤 2：配置 .env
```env
SMTP_HOST=smtp.163.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=your_email@163.com
SMTP_PASS=授权密码
SMTP_FROM_NAME=CWH 下载站
```

### 4. 其他邮箱服务商

| 服务商 | SMTP 地址 | 端口 | SSL |
|--------|-----------|------|-----|
| Outlook | smtp-mail.outlook.com | 587 | false |
| Yahoo | smtp.mail.yahoo.com | 587 | false |
| 阿里云邮箱 | smtp.aliyun.com | 465 | true |
| 腾讯企业邮箱 | smtp.exmail.qq.com | 465 | true |

## 测试邮件发送

启动后端后，可以通过注册页面测试：

1. 输入邮箱地址
2. 点击"发送验证码"
3. 检查邮箱是否收到验证码

## 常见问题

### 1. 邮件发送失败

**检查：**
- SMTP 配置是否正确
- 应用专用密码是否正确（不是邮箱登录密码）
- 网络是否能访问 SMTP 服务器
- 查看后端日志错误信息

### 2. 收不到邮件

**检查：**
- 垃圾邮件文件夹
- 邮箱是否正确
- SMTP 服务是否开启
- 邮箱是否有发送限制

### 3. 验证码过期

验证码有效期为 5 分钟，过期后需要重新发送。

### 4. 发送频率限制

为防止滥用，同一邮箱 60 秒内只能发送一次验证码。

## 安全建议

1. **不要泄露 SMTP 密码**
   - 不要将 `.env` 文件提交到 Git
   - 使用应用专用密码，不要使用邮箱登录密码

2. **使用环境变量**
   - 生产环境使用环境变量而不是 `.env` 文件
   - 定期更换 SMTP 密码

3. **限制发送频率**
   - 已实现 60 秒冷却时间
   - 可以根据需要调整

## 数据库表

邮箱验证码存储在 `email_verifications` 表：

```sql
CREATE TABLE email_verifications (
  id INT PRIMARY KEY AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL,
  code VARCHAR(6) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

验证码会在以下情况被删除：
- 注册成功后
- 过期后（5 分钟）
- 发送新验证码时

## 邮件模板

验证码邮件使用 HTML 模板，包含：
- 品牌标识
- 验证码（6 位数字）
- 有效期提示
- 安全提示

可以在 `backend/src/utils/email.js` 中自定义邮件模板。
