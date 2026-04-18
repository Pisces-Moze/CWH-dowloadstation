import crypto from 'crypto'
import fs from 'fs'
import stream from 'stream'
import { promisify } from 'util'

const pipeline = promisify(stream.pipeline)

// 从环境变量获取加密密钥，如果没有则生成一个
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY 
  ? Buffer.from(process.env.ENCRYPTION_KEY, 'hex')
  : crypto.randomBytes(32)

const ALGORITHM = 'aes-256-cbc'

// 加密文件
export async function encryptFile(inputPath, outputPath) {
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv)
  
  await pipeline(
    fs.createReadStream(inputPath),
    cipher,
    fs.createWriteStream(outputPath)
  )
  
  // 删除原文件
  fs.unlinkSync(inputPath)
  
  return iv.toString('hex')
}

// 解密文件流（用于下载）
export function createDecryptStream(iv) {
  const ivBuffer = Buffer.from(iv, 'hex')
  return crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, ivBuffer)
}

// 生成分享码
export function generateShareCode() {
  return crypto.randomBytes(16).toString('hex')
}

// 验证分享码格式
export function isValidShareCode(code) {
  return /^[a-f0-9]{32}$/.test(code)
}

// 计算加密文件的 MD5（解密后的内容）
export async function calculateFileMD5(filePath, iv) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('md5')
    const decryptStream = createDecryptStream(iv)
    const fileStream = fs.createReadStream(filePath)

    fileStream.pipe(decryptStream).on('data', (chunk) => {
      hash.update(chunk)
    }).on('end', () => {
      resolve(hash.digest('hex'))
    }).on('error', reject)
  })
}
