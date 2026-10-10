(() => {
  const root = document.documentElement;
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  let stored = null;
  try {
    stored = localStorage.getItem("upt-theme");
  } catch (_) {
    // Appearance still follows the current system preference if storage is
    // unavailable in a restricted/private browser context.
  }
  let preference = ["system", "light", "dark"].includes(stored) ? stored : "system";

  const apply = () => {
    const resolved = preference === "system"
      ? (media.matches ? "dark" : "light")
      : preference;
    root.dataset.themePreference = preference;
    root.dataset.theme = resolved;
    root.dataset.bsTheme = resolved;
  };

  window.uptTheme = {
    get preference() {
      return preference;
    },
    set(value) {
      if (!["system", "light", "dark"].includes(value)) return;
      preference = value;
      try {
        localStorage.setItem("upt-theme", value);
      } catch (_) {
        // Keep the current page usable when the browser blocks local storage.
      }
      apply();
    },
  };

  apply();
  const onSystemThemeChange = () => {
    if (preference === "system") apply();
  };
  if (media.addEventListener) media.addEventListener("change", onSystemThemeChange);
  else media.addListener(onSystemThemeChange);

  document.addEventListener("DOMContentLoaded", () => {
    const select = document.querySelector("[data-theme-select]");
    if (!select) return;
    select.value = preference;
    select.addEventListener("change", () => window.uptTheme.set(select.value));
  });
})();
