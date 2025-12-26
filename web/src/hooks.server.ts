import { initAuth, getAuth } from "$lib/auth";
import { svelteKitHandler } from "better-auth/svelte-kit";
import { building } from "$app/environment";
import { error } from "@sveltejs/kit";

import type { Handle } from "@sveltejs/kit";

export const handle: Handle = async ({ event, resolve }) => {
  try {
    const db = event.platform?.env?.DB;
    if (!db) {
      console.error('D1 database not available - check alchemy/cloudflare/sveltekit adapter');
      return error(500, 'D1 database not available');
    }

    const auth = initAuth(db, event.platform?.env);

    try {
      const session = await auth.api.getSession({
        headers: event.request.headers,
      });
      event.locals.user = session?.user || null;
      event.locals.session = session?.session || null;
    } catch (sessionError) {
      console.error('Session loading error:', sessionError);
      event.locals.user = null;
      event.locals.session = null;
    }

    const theme = event.cookies.get('theme') || 'light';
    event.locals.theme = theme as 'light' | 'dark';

    return await svelteKitHandler({ 
      event, 
      resolve: async (event) => {
        const response = await resolve(event, {
          transformPageChunk: ({ html }) => {
            if (theme === 'dark') {
              if (html.includes('<html')) {
                if (html.includes('<html class=')) {
                  return html.replace(/<html class="([^"]*)"/, '<html class="$1 dark"');
                } else {
                  return html.replace('<html', '<html class="dark"');
                }
              }
            }
            return html;
          }
        });
        return response;
      }, 
      auth, 
      building 
    });

  } catch (err) {
    console.error(err);
    return error(500, 'Service temporarily unavailable');
  }
};
