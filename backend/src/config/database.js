import mysql from 'mysql2/promise'
import dotenv from 'dotenv'

dotenv.config()

const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'users',
  connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 10,
  waitForConnections: true,
  queueLimit: 0
})

// 初始化数据库表
async function initDatabase() {
  try {
    const connection = await pool.getConnection()
    
    // 角色表
    await connection.query(`
      CREATE TABLE IF NOT EXISTS roles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE,
        display_name VARCHAR(100) NOT NULL,
        storage_quota BIGINT DEFAULT 3221225472,
        can_delete_public_files BOOLEAN DEFAULT FALSE,
        can_manage_users BOOLEAN DEFAULT FALSE,
        can_view_stats BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `)

    // 插入默认角色
    await connection.query(`
      INSERT IGNORE INTO roles (name, display_name, storage_quota, can_delete_public_files, can_manage_users, can_view_stats)
      VALUES 
        ('admin', '管理员', 3221225472, TRUE, TRUE, TRUE),
        ('user', '普通用户', 3221225472, FALSE, FALSE, FALSE)
    `)

    // 用户表（扩展）
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        role_id INT DEFAULT 2,
        avatar_file_id INT NULL,
        bio TEXT,
        storage_used BIGINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (role_id) REFERENCES roles(id),
        INDEX idx_username (username),
        INDEX idx_email (email),
        INDEX idx_role_id (role_id)
      )
    `)

    // 检查是否存在管理员账户
    const [admins] = await connection.query(`
      SELECT COUNT(*) as count FROM users u
      JOIN roles r ON u.role_id = r.id
      WHERE r.name = 'admin'
    `)

    // 如果没有管理员，创建默认管理员
    if (admins[0].count === 0) {
      const crypto = await import('crypto')
      const defaultPassword = crypto.randomBytes(8).toString('hex')
      
      await connection.query(`
        INSERT INTO users (username, password, email, role_id)
        VALUES ('admin', ?, 'admin@localhost', 1)
      `, [defaultPassword])
      
      console.log('\n🔐 默认管理员账户已创建：')
      console.log('   用户名: admin')
      console.log('   密码:', defaultPassword)
      console.log('   ⚠️  请立即登录并修改密码！\n')
    }

    // 文件表
    await connection.query(`
      CREATE TABLE IF NOT EXISTS files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        filename VARCHAR(255) NOT NULL,
        original_name VARCHAR(255) NOT NULL,
        size BIGINT NOT NULL,
        mime_type VARCHAR(100),
        downloads INT DEFAULT 0,
        is_private BOOLEAN DEFAULT FALSE,
        encryption_iv VARCHAR(32),
        md5 VARCHAR(32),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id),
        INDEX idx_created_at (created_at),
        INDEX idx_is_private (is_private)
      )
    `)

    // 分享链接表
    await connection.query(`
      CREATE TABLE IF NOT EXISTS share_links (
        id INT AUTO_INCREMENT PRIMARY KEY,
        file_id INT NOT NULL,
        share_code VARCHAR(32) NOT NULL UNIQUE,
        password VARCHAR(255),
        expires_at TIMESTAMP NULL,
        downloads INT DEFAULT 0,
        max_downloads INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
        INDEX idx_share_code (share_code),
        INDEX idx_file_id (file_id)
      )
    `)

    // 文件引用表（转存功能）
    await connection.query(`
      CREATE TABLE IF NOT EXISTS file_references (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        original_file_id INT NOT NULL,
        reference_name VARCHAR(255),
        downloads INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (original_file_id) REFERENCES files(id) ON DELETE CASCADE,
        UNIQUE KEY unique_user_file (user_id, original_file_id),
        INDEX idx_user_id (user_id),
        INDEX idx_original_file_id (original_file_id)
      )
    `)

    // 访客统计表
    await connection.query(`
      CREATE TABLE IF NOT EXISTS visitor_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        session_id VARCHAR(64) NOT NULL UNIQUE,
        user_id INT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_session_id (session_id),
        INDEX idx_last_activity (last_activity)
      )
    `)

    // 文件下载日志表
    await connection.query(`
      CREATE TABLE IF NOT EXISTS download_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        file_id INT NOT NULL,
        user_id INT NULL,
        ip_address VARCHAR(45),
        downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_file_id (file_id),
        INDEX idx_downloaded_at (downloaded_at)
      )
    `)

    connection.release()
    console.log('✅ Database initialized successfully')
  } catch (error) {
    console.error('❌ Database initialization failed:', error)
    throw error
  }
}

initDatabase()

export default pool
