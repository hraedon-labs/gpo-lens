// patina:sha256 91c2491e26c82518114eb43bf900f917e2a3e3189eb20724ac5e51001ccf52cf rev:1dffec1
/* patina theme toggle -- shared across the tool family.
   Load this synchronously in <head> (before the stylesheet) so the theme is
   applied before first paint and there is no flash. The family CSP is
   script-src 'self', which forbids inline JS, so this lives as a file.

   The localStorage key defaults to "patina-theme"; a tool can scope its own by
   setting <html data-theme-key="cw-theme"> (so multiple family apps on one
   origin do not share a preference unexpectedly). Default theme is dark.
   Other tabs using the same key follow saved changes; unrelated tool keys
   and sessionStorage events do not affect this tool. */
(function () {
  var root = document.documentElement;
  var KEY = root.getAttribute("data-theme-key") || "patina-theme";
  function get() {
    try {
      var stored = localStorage.getItem(KEY);
      return stored === "light" || stored === "dark" ? stored : "dark";
    } catch (e) { return "dark"; }
  }
  function apply(t) { root.setAttribute("data-theme", t); }

  apply(get());

  function updateControl() {
    var dark = root.getAttribute("data-theme") === "dark";
    var d = document.getElementById("theme-icon-dark");
    var l = document.getElementById("theme-icon-light");
    if (d) d.style.display = dark ? "none" : "block";
    if (l) l.style.display = dark ? "block" : "none";
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      var action = dark ? "Switch to light theme" : "Switch to dark theme";
      btn.setAttribute("aria-label", action);
      btn.setAttribute("title", action);
    }
  }

  window.addEventListener("storage", function (event) {
    if (event.key !== KEY && event.key !== null) return;
    try { if (event.storageArea !== localStorage) return; } catch (e) { return; }
    // Read the latest preference: queued events can describe an older value.
    // Do not write it back, which would create needless cross-tab events.
    apply(get());
    updateControl();
  });

  function wire() {
    updateControl();
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      apply(next);
      try { localStorage.setItem(KEY, next); } catch (e) {}
      updateControl();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
