// (A) 创建/安装缓存
self.addEventListener("install", evt => {
    // 跳过等待，立即激活
    self.skipWaiting();
    // 等待直到缓存打开，然后将所需资源添加到缓存中
    evt.waitUntil(
      caches.open("CWH")
      .then(cache => cache.addAll([
        "index.html",
      ]))
      .catch(err => console.error(err))
    );
  });
   
  // (B) 立即接管控制权
  self.addEventListener("activate", evt => self.clients.claim());
   
  // (C) 首先从网络加载，如果离线则回退到缓存
  self.addEventListener("fetch", evt => evt.respondWith(
    fetch(evt.request).catch(() => caches.match(evt.request))
  ));