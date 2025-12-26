import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ request, cookies }) => {
  const { theme } = await request.json();
  
  if (theme !== 'light' && theme !== 'dark') {
    return json({ error: 'Invalid theme' }, { status: 400 });
  }
  
  cookies.set('theme', theme, {
    path: '/',
    maxAge: 60 * 60 * 24 * 365,
    sameSite: 'lax',
    httpOnly: false
  });
  
  return json({ success: true, theme });
};




