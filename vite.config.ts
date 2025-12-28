import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [sveltekit(), tailwindcss()],
  server: {
    port: 5177,
    strictPort: true,
    watch: {
      ignored: ['**/app/**', '**/.alchemy/**', '**/node_modules/**']
    }
  }
});

