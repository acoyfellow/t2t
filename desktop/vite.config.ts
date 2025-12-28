import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [sveltekit(), tailwindcss()],
  server: {
    port: 5177,
    strictPort: true,
    fs: {
      allow: [
        '../node_modules',
        './node_modules',
        './src',
        './.svelte-kit'
      ]
    },
    watch: {
      ignored: ['**/web/**', '**/../web/**', '**/node_modules/**']
    }
  }
});

