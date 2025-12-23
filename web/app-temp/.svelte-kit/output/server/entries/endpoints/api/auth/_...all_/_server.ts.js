import { i as initAuth } from "../../../../../chunks/auth.js";
const GET = async ({ request, platform }) => {
  const auth = initAuth(platform?.env?.DB, platform?.env);
  return auth.handler(request);
};
const POST = async ({ request, platform }) => {
  const auth = initAuth(platform?.env?.DB, platform?.env);
  return auth.handler(request);
};
export {
  GET,
  POST
};
