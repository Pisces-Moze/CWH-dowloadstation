<template>
  <footer class="app-footer">
    <div class="footer-content">
      <div class="footer-info">
        <p>© 2026 CWH 下载站 - 企业级文件管理系统</p>
        <p class="footer-links">
          <a href="https://github.com/Pisces-Moze/CWH-dowloadstation" target="_blank">GitHub</a>
          <span>·</span>
          <a href="https://blog.pmoze.top" target="_blank">博客</a>
          <span>·</span>
          <span>Made with ❤️ by 沫然</span>
        </p>
      </div>
    </div>
  </footer>
</template>

<style scoped>
.app-footer {
  background: white;
  border-top: 1px solid #e8e8e8;
  margin-top: 40px;
}

.footer-content {
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px 20px;
  text-align: center;
}

.footer-info p {
  margin: 8px 0;
  color: #666;
  font-size: 14px;
}

.footer-links {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.footer-links a {
  color: #667eea;
  text-decoration: none;
  transition: color 0.3s;
}

.footer-links a:hover {
  color: #764ba2;
}

@media (max-width: 768px) {
  .footer-content {
    padding: 16px 10px;
  }

  .footer-info p {
    font-size: 12px;
  }
}
</style>
