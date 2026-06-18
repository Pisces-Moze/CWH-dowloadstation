import { createRouter, createWebHistory } from 'vue-router'
import { useUserStore } from '../stores/user'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: () => import('../views/Home.vue'),
    meta: { title: 'CWH 下载站' }
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    meta: { title: '登录', guest: true }
  },
  {
    path: '/register',
    name: 'Register',
    component: () => import('../views/Register.vue'),
    meta: { title: '注册', guest: true }
  },
  {
    path: '/private',
    name: 'Private',
    component: () => import('../views/Private.vue'),
    meta: { title: '私人空间', requiresAuth: true }
  },
  {
    path: '/profile',
    name: 'Profile',
    component: () => import('../views/Profile.vue'),
    meta: { title: '个人资料', requiresAuth: true }
  },
  {
    path: '/profile/:userId',
    name: 'UserProfile',
    component: () => import('../views/UserProfile.vue'),
    meta: { title: '用户资料' }
  },
  {
    path: '/admin',
    name: 'Admin',
    component: () => import('../views/Admin.vue'),
    meta: { title: '管理员控制面板', requiresAuth: true, requiresAdmin: true }
  },
  {
    path: '/share/:code',
    name: 'Share',
    component: () => import('../views/Share.vue'),
    meta: { title: '分享文件' }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 路由守卫
router.beforeEach(async (to, from, next) => {
  const userStore = useUserStore()
  
  // 设置页面标题
  document.title = to.meta.title || 'CWH 下载站'
  
  // 如果已登录且访问登录/注册页，重定向到首页
  if (to.meta.guest && userStore.isLoggedIn) {
    return next('/')
  }
  
  // 需要登录的页面
  if (to.meta.requiresAuth && !userStore.isLoggedIn) {
    return next('/login')
  }
  
  // 需要管理员权限的页面
  if (to.meta.requiresAdmin) {
    if (!userStore.user) {
      await userStore.fetchProfile()
    }
    if (!userStore.isAdmin) {
      return next('/')
    }
  }
  
  next()
})

export default router
