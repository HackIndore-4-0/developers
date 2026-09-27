import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'
import { createProxyMiddleware } from 'http-proxy-middleware'

// Custom plugin to add the dynamic proxy to the Vite Dev Server
const dynamicProxyPlugin = () => ({
  name: 'dynamic-proxy',
  configureServer(server) {
    server.middlewares.use(
      '/dynamic-proxy',
      createProxyMiddleware({
        router: (req) => req.headers['x-target-base-url'] || 'https://192.168.137.39:3443',
        changeOrigin: true,
        secure: false, // Bypass SSL cert errors
        pathRewrite: { '^/dynamic-proxy': '' },
        onProxyReq: (proxyReq) => {
          proxyReq.removeHeader('x-target-base-url');
        }
      })
    );
  }
});

export default defineConfig({
  plugins: [react(), tailwindcss(), dynamicProxyPlugin()],
  server: {
    allowedHosts: true,
    hmr: false,
    proxy: {
      // Legacy Twilio route
      '/twilio': {
        target: 'https://api.twilio.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/twilio/, ''),
      }
    }
  }
})
