import path from "path"
import { defineConfig } from 'vite'
import { viteSingleFile } from 'vite-plugin-singlefile'
import react from '@vitejs/plugin-react-swc'

export default defineConfig({
  plugins: [
    react(),
    viteSingleFile()
  ],
  base: './', // Ensures relative paths for assets
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Ignore macOS system files
  server: {
    fs: {
      deny: ['.DS_Store']
    }
  },
  build: {
    outDir: 'docs',
    emptyOutDir: true,
    rollupOptions: {
        output: {
            // Forces everything into one file
            manualChunks: undefined,
        },
    },
  }
})