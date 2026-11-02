import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

// The build is embedded in the Go binary (web/embed.go). During `npm run dev`
// API calls go to a running `security-warden serve`.
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  build: { outDir: 'dist', emptyOutDir: false, assetsInlineLimit: 0, sourcemap: false },
  server: { proxy: { '/api': 'http://127.0.0.1:7878', '/login': 'http://127.0.0.1:7878' } },
})
