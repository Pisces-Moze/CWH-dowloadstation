import nodemailer from 'nodemailer'
import dotenv from 'dotenv'

dotenv.config()

// 创建邮件传输器
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
})

// 发送邮件
export async function sendEmail(to, subject, html) {
  try {
    const info = await transporter.sendMail({
      from: `"${process.env.SMTP_FROM_NAME || 'CWH 下载站'}" <${process.env.SMTP_USER}>`,
      to,
      subject,
      html
    })
    console.log('邮件发送成功:', info.messageId)
    return { success: true, messageId: info.messageId }
  } catch (error) {
    console.error('邮件发送失败:', error)
    return { success: false, error: error.message }
  }
}

// 生成验证码
export function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

// 发送验证码邮件
export async function sendVerificationCode(email, code) {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .code { background: white; border: 2px dashed #667eea; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; color: #667eea; margin: 20px 0; letter-spacing: 5px; }
        .footer { text-align: center; margin-top: 20px; color: #999; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>CWH 下载站</h1>
          <p>邮箱验证码</p>
        </div>
        <div class="content">
          <p>您好！</p>
          <p>您正在注册 CWH 下载站账户，您的验证码是：</p>
          <div class="code">${code}</div>
          <p><strong>验证码有效期为 5 分钟</strong>，请尽快完成验证。</p>
          <p>如果这不是您的操作，请忽略此邮件。</p>
        </div>
        <div class="footer">
          <p>此邮件由系统自动发送，请勿回复</p>
          <p>© 2026 CWH 下载站</p>
        </div>
      </div>
    </body>
    </html>
  `
  
  return await sendEmail(email, '【CWH 下载站】邮箱验证码', html)
}
