import { writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

export type Theme = "light" | "dark" | "system";

export const theme = writable<Theme>("system");

let systemTheme: "light" | "dark" = "light";

export const resolvedTheme = writable<"light" | "dark">("light");

// Load theme from store
export async function loadTheme() {
  try {
    const savedTheme = (await invoke("get_theme")) as string;
    theme.set(savedTheme as Theme);

    // Get initial system theme
    const sysTheme = (await invoke("get_system_theme")) as string;
    systemTheme = sysTheme as "light" | "dark";
    updateResolvedTheme(savedTheme as Theme);
  } catch (e) {
    console.error("Failed to load theme:", e);
  }
}

// Save theme to store
export async function saveTheme(newTheme: "light" | "dark" | "system") {
  try {
    await invoke("set_theme", { theme: newTheme });
    theme.set(newTheme);
    updateResolvedTheme(newTheme);
  } catch (e) {
    console.error("Failed to save theme:", e);
  }
}

function updateResolvedTheme(currentTheme: Theme) {
  if (currentTheme === "system") {
    resolvedTheme.set(systemTheme);
  } else {
    resolvedTheme.set(currentTheme);
  }
}

// Subscribe to theme changes to update resolved theme
let unsubscribeTheme: (() => void) | null = null;
if (typeof window !== "undefined") {
  unsubscribeTheme = theme.subscribe((currentTheme) => {
    updateResolvedTheme(currentTheme);
  });

  // Listen for system theme changes
  const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
  const handleChange = async () => {
    const sysTheme = (await invoke("get_system_theme")) as string;
    systemTheme = sysTheme as "light" | "dark";
    theme.subscribe((currentTheme) => {
      updateResolvedTheme(currentTheme);
    })();
  };
  mediaQuery.addEventListener("change", handleChange);
}
