type Theme = 'light' | 'dark';

function getSystemTheme(): Theme {
  if (typeof window === 'undefined') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function getStoredTheme(): Theme | null {
  if (typeof window === 'undefined') return null;
  const stored = localStorage.getItem('theme');
  return stored === 'dark' || stored === 'light' ? stored : null;
}

export function getTheme(): Theme {
  const stored = getStoredTheme();
  if (stored) return stored;
  return getSystemTheme();
}

export function setTheme(theme: Theme) {
  if (typeof window === 'undefined') return;
  
  localStorage.setItem('theme', theme);
  
  const html = document.documentElement;
  if (theme === 'dark') {
    html.classList.add('dark');
  } else {
    html.classList.remove('dark');
  }
  
  fetch('/api/theme', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ theme })
  }).catch(() => {});
}

export function syncTheme() {
  const currentTheme = getTheme();
  setTheme(currentTheme);
}

export function initializeTheme(serverTheme: Theme | null) {
  if (typeof window === 'undefined') return;
  
  const stored = getStoredTheme();
  const system = getSystemTheme();
  
  let theme: Theme;
  if (stored) {
    theme = stored;
  } else if (serverTheme) {
    theme = serverTheme;
  } else {
    theme = system;
  }
  
  setTheme(theme);
  
  if (!stored && theme !== serverTheme) {
    fetch('/api/theme', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ theme })
    }).catch(() => {});
  }
}




