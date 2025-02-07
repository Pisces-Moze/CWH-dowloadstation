const fs = require('fs');
const fsPromises = require('fs').promises;
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const jschardet = require('jschardet');
const https = require('https');
const iconv = require('iconv-lite');
const crypto = require('crypto');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');


const app = express();
const port = 1145; // 修改端口，避免与第一个代码冲突
const options = {
    key: fs.readFileSync('key/dls.furxxdls.icu.key'),
    cert: fs.readFileSync('key/dls.furxxdls.icu.pem')
};

app.use(cors());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
const Secret = crypto.randomBytes(64).toString('hex');
const jwtSecret = Secret;



function getCurrentTimestamp() {
    const now = new Date();
    const formattedDate = now.toISOString().replace(/:/g, '-').slice(0, -5);
    return formattedDate;
}

// MySQL 连接配置
const pool = mysql.createPool({
    connectionLimit: 10,
    host: '127.0.0.1',
    user: 'root',
    password: '',
    database: 'users'
}); 

// 创建数据库表（如果不存在）
const createTableQuery = `
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL
);`;

pool.getConnection((err, connection) => {
    if (err) {
        console.error('Error getting database connection: ' + err.stack);
        return;
    }

    connection.query(createTableQuery, (err, result) => {
        connection.release(); // 释放连接
        if (err) {
            console.error('Error creating table: ' + err.stack);
            return;
        }
        console.log('Table created successfully');
    });
});


// 设置文件上传
const uploadFolder = path.join(__dirname, 'uploads');
const configFolder = path.join(__dirname, 'config');
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const filenameBuffer = Buffer.from(file.originalname, 'binary');
        const detectedResult = jschardet.detect(filenameBuffer);
        const detectedEncoding = detectedResult.encoding;
        const utf8Filename = iconv.decode(filenameBuffer, detectedEncoding);
        cb(null, utf8Filename);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 1 * 1024 * 1024 * 1024 * 1024, // 1TB
    },
});

// 创建上传和配置文件夹
async function createUploadFolder() {
    try {
        await fsPromises.access(uploadFolder);
    } catch (error) {
        if (error.code === 'ENOENT') {
            await fsPromises.mkdir(uploadFolder);
        } else {
            console.error('Error accessing upload folder:', error);
        }
    }
}

async function createConfigFolder() {
    try {
        await fsPromises.access(configFolder);
    } catch (error) {
        if (error.code === 'ENOENT') {
            await fsPromises.mkdir(configFolder);
        } else {
            console.error('Error accessing config folder:', error);
        }
    }
}

createUploadFolder();
createConfigFolder();

// 处理文件上传
app.post('/upload', upload.array('file', 10), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            // 如果 req.files 不存在，返回错误响应
            return res.status(400).send({ message: '未找到上传的文件' });
        }

        const filenames = req.files.map(file => file.filename);

        const fileDetails = [];
        for (const filename of filenames) {
            const filePath = path.join(uploadFolder, filename);

            const stat = await fsPromises.stat(filePath);
            const md5 = await calculateMD5(filePath);
            

            // 创建配置文件
            const configFilePath = path.join(configFolder, `${filename}.json`);

            const authorizationHeader = req.headers['authorization'];
            if (!authorizationHeader) {
                return res.status(401).send('Authorization header is missing');
            }
            const token = authorizationHeader.split(' ')[1];
            let decodedToken;
            try {
                // 解码 JWT 令牌
                decodedToken = jwt.verify(token, jwtSecret);
            } catch (error) {
                // 如果解码失败，返回错误响应
                return res.status(401).send('Invalid JWT token');
            }
            const username = decodedToken.username;
            const configData = {
                fileSize: stat.size,
                uploadTime: stat.birthtimeMs,
                md5: md5,
                uploader: username
            };
            await fsPromises.writeFile(configFilePath, JSON.stringify(configData));

            fileDetails.push({
                name: filename,
                size: stat.size,
                uploadTime: stat.birthtimeMs,
                md5: md5,
                uploader: username
            });
        }

        res.status(200).send({ message: '文件上传成功！', files: fileDetails });
    } catch (error) {
        console.error('Error processing uploaded file:', error);
        res.status(500).send('Internal Server Error');
    }
});

// 获取文件列表
app.get('/fileList', async (req, res) => {
    try {
        const files = await fsPromises.readdir(uploadFolder);
        const filesDetails = [];

        for (const file of files) {
            const filePath = path.join(uploadFolder, file);
            const stat = await fsPromises.stat(filePath);

            // 读取配置文件
            const configFilePath = path.join(configFolder, `${file}.json`);
            let md5 = '';
            let fileSize = 'N/A';
            let uploadTime = 'N/A';
            let uploader = 'N/A';
           

            try {
                const configData = await fsPromises.readFile(configFilePath, 'utf-8');
                const parsedConfigData = JSON.parse(configData);
                md5 = parsedConfigData.md5;
                fileSize = parsedConfigData.fileSize;
                uploadTime = parsedConfigData.uploadTime;
                uploader = parsedConfigData.uploader;
            } catch (configError) {
                // 如果没有配置文件，重新计算 MD5 并保存配置文件
                md5 = await calculateMD5(filePath);
                const configData = {
                    fileSize: stat.size,
                    uploadTime: stat.birthtimeMs,
                    md5: md5
                };
                await fsPromises.writeFile(configFilePath, JSON.stringify(configData));
            }

            filesDetails.push({
                name: file,
                size: fileSize,
                uploadTime: uploadTime,
                md5: md5,
                uploader: uploader 
            });
        }

        res.json({ files: filesDetails });
    } catch (error) {
        console.error('Error fetching file list:', error);
        res.status(200).json({ message: '注册成功！' });

    }
});

// 下载文件
app.get('/download/:filename', async (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadFolder, filename);

    try {
        const stat = await fsPromises.stat(filePath);
        const stream = fs.createReadStream(filePath);

        stream.on('error', (err) => {
            if (err.code === 'EPIPE') {
                // 用户取消下载，不做处理
                console.log('Download cancelled by client');
            } else {
                console.error('Error downloading file:', err);
                res.status(500).send('Internal Server Error');
            }
        });

        const encodedFilename = encodeURIComponent(filename);
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodedFilename}`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', stat.size);

        stream.pipe(res);
    } catch (error) {
        console.error('Error accessing file:', error);
        res.status(404).send('File not found');
    }
});

// 创建邮箱传输对象
const transporter = nodemailer.createTransport({
    host: 'smtp.qq.com', // Outlook SMTP服务器地址
    port: 587, // Outlook SMTP服务器端口号
    secure: false, // 不使用SSL加密
    auth: {
        user: '2907829820@qq.com', // 发送验证码的邮箱
        pass: 'rqrlgefxexyhdfba' // 邮箱密码或授权码
    }
});

// 生成随机验证码函数
function generateVerificationCode(length) {
    const chars = '0123456789';
    let code = '';
    for (let i = 0; i < length; i++) {
        code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code;
}

// 存储验证码的对象，以邮箱为键，值为 { code: 验证码, timestamp: 生成时间戳 }
const verificationCodes = {};

// 发送验证码路由
app.post('/sendVerificationCode', (req, res) => {
    const { email } = req.body;

    // 生成验证码
    const code = generateVerificationCode(6);
    verificationCodes[email] = { code: code, timestamp: Date.now() };

    // 发送邮件
    const mailOptions = {
        from: '2907829820@qq.com', // 发送验证码的邮箱
        to: email,
        subject: '验证您的 CloudWisHub 账号',
        html: `
            <h2 style="font-weight: 400;">CWH智享云阁 <small style="font-size: 16px;">公益、稳定、轻量的公益下载站</small></h2>
            <div style="width:100%;height:1px;border-top: 1px dashed rgba(0,0,0,0.3);"></div>
            <p>感谢您注册 智享云阁，为了防止我们的服务被滥用，我们需要对您的电子邮件账号进行验证，您只在注册页面输入以下数字即可验证。验证码有效期为 15 分钟，请尽快完成注册。</p>
            <p style="font-size: 20px;"><code>${code}</code></p>
            <p>此邮件由系统自动发送，请勿直接回复，如果您没有注册过本站账号，请无视此邮件。</p>
            <p>如有问题请通过站点上的联系方式联系我们。</p>
            <div style="width:100%;height:1px;border-top: 1px dashed rgba(0,0,0,0.3);"></div>
            <p style="text-align: right;">CyberPawsTeam</p>
        `
    };
    

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
            res.status(200).json({ success: false, error: '发送验证码失败' });
        } else {
            console.log('Email sent: ' + info.response);
            res.status(200).json({ success: true });
        }
    });
});


// 用户注册
app.post('/register', (req, res) => {
    const { username, password, email, emailCode } = req.body;
    // 从连接池中获取连接
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection: ' + err.stack);
            res.status(500).json({ success: false, error: 'Internal Server Error' });
            return;
        }

// 验证邮箱验证码
    const storedCode = verificationCodes[email];
    if (!storedCode) {
        res.status(200).json({ success: false, message: '邮箱验证码不存在或已过期' });
        return;
    }
    console.log("storedCode:", storedCode);



// 验证验证码是否超过15分钟有效期
    const timestamp = storedCode.timestamp;
    const currentTime = Date.now();
    const fifteenMinutes = 15 * 60 * 1000; // 15分钟的毫秒数
    if (!storedCode || !storedCode.timestamp || Date.now() - storedCode.timestamp > 15 * 60 * 1000) {
        res.status(200).json({ success: false, message: '邮箱验证码不存在或已过期' });
        return;
    }


    

// 确保验证码正确
    if (storedCode.code !== emailCode) {
        res.status(200).json({ success: false, message: '邮箱验证码错误' });
        return;
    }

// **只有在验证码验证通过后再删除**
    delete verificationCodes[email];

        // 检查是否存在相同的用户名
        const checkQuery = 'SELECT * FROM users WHERE username = ?';
        connection.query(checkQuery, [username], (err, results) => {
            if (err) {
                console.error('Error checking user: ' + err.stack);
                res.status(500).json({ success: false, error: '网络错误ID：341' });
                connection.release();
                return;
            }



            if (results.length > 0) {
                // 用户名已存在，返回错误
                res.status(200).json({ success: false, message: '用户名存在了惹～' });
                connection.release();
                return;
            }

            // 用户名不存在，进行注册
            const insertQuery = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
            connection.query(insertQuery, [username, password, email], (err, result) => {
                connection.release(); // 释放连接
                if (err) {
                    console.error('Error inserting user: ' + err.stack);
                    res.status(500).json({ success: false, error: '网络错误ID：361' });
                    return;
                }
                console.log('User registered successfully');
                // 注册成功返回成功消息
                res.status(200).json({ success: true });
            });
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // 从连接池中获取连接
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting database connection: ' + err.stack);
            res.status(500).json({ success: false, error: '网络错误，似了xwx ID:380' });
            return;
        }

        const selectQuery = 'SELECT * FROM users WHERE username = ? AND password = ?';
        connection.query(selectQuery, [username, password], (err, result) => {
            connection.release(); // 释放连接
            if (err) {
                console.error('Error querying database: ' + err.stack);
                res.status(500).json({ success: false, error: '网络错误，似了xwx ID:389' });
                return;
            }
            if (result.length > 0) {
                const user = { username: username };
                const accessToken = jwt.sign(user, jwtSecret);
                const token = jwt.sign({ username }, jwtSecret, { expiresIn: '7d' });
                res.cookie('access_token', accessToken, { maxAge: 900000, httpOnly: false });
                res.status(200).json({ success: true, username: username }); // 返回用户名
            } else {
                // 登录失败
                res.status(200).json({ success: false, message: '检查用户名和密码捏awa' });
            }
        });
    });
});

// 验证会话令牌中间件
function authenticateToken(req, res, next) {
    const token = req.cookies.access_token;
    if (token == null) return res.sendStatus(401); // 没有令牌，返回未授权状态

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.sendStatus(403); // 令牌验证失败，返回禁止访问状态
        req.user = user;
        next(); // 令牌验证通过，继续执行下一个中间件
    });
}

// 保护的路由，需要验证会话令牌
app.get('/protected_route', authenticateToken, (req, res) => {
    // 从 req.user 中获取用户名
    const username = req.user.username;
    res.json({ message: '受保护的路由，令牌验证通过！', username: username });
});

// 配置 Express 提供静态文件
app.use(express.static('public'));

// 启动 HTTPS 服务器
https.createServer(options, app).listen(port, () => {
    console.log('狐物器，启动！ 进入： ${port}');
});

// 计算文件的 MD5
async function calculateMD5(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('md5');
        const stream = fs.createReadStream(filePath);

        stream.on('data', (chunk) => {
            hash.update(chunk);
        });

        stream.on('error', (err) => {
            reject(err);
        });

        stream.on('end', () => {
            const md5 = hash.digest('hex');
            resolve(md5);
        });
    });
}
