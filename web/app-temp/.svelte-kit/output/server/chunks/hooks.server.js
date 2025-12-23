import { i as initAuth, s as svelteKitHandler } from "./auth.js";
import { b as building } from "./environment.js";
import { error } from "@sveltejs/kit";
const handle = async ({ event, resolve }) => {
  try {
    const db = event.platform?.env?.DB;
    if (!db) {
      console.error("D1 database not available - check alchemy/cloudflare/sveltekit adapter");
      return error(500, "D1 database not available");
    }
    const auth = initAuth(db, event.platform?.env);
    try {
      const session = await auth.api.getSession({
        headers: event.request.headers
      });
      event.locals.user = session?.user || null;
      event.locals.session = session?.session || null;
    } catch (sessionError) {
      console.error("Session loading error:", sessionError);
      event.locals.user = null;
      event.locals.session = null;
    }
    const response = await svelteKitHandler({ event, resolve, auth, building });
    return response;
  } catch (err) {
    console.error(err);
    return error(500, "Service temporarily unavailable");
  }
};
export {
  handle
};
