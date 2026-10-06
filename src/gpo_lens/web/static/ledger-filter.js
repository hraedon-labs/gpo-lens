/* WI-1 — Settings ledger type-to-filter.
   Dependency-free: finds the ledger table, filters rows by substring
   across identity/name/value/registry fields.  Works with no-JS: the
   full table renders server-side and the filter input is a progressive
   enhancement. */
(function () {
  "use strict";
  var input = document.querySelector("[data-ledger-filter]");
  if (!input) return;
  var rows = document.querySelectorAll(".gp-ledger-row");
  var countEl = document.querySelector("[data-ledger-count]");
  var total = rows.length;

  function filter() {
    var q = input.value.toLowerCase().trim();
    document.querySelectorAll("[data-ledger-export]").forEach(function (link) {
      var url = new URL(link.href);
      url.searchParams.set("ledger_q", input.value.trim());
      link.href = url.toString();
    });
    var visible = 0;
    rows.forEach(function (row) {
      var hay = row.getAttribute("data-ledger-search") || "";
      if (!q || hay.indexOf(q) !== -1) {
        row.hidden = false;
        visible++;
      } else {
        row.hidden = true;
      }
    });
    if (countEl) {
      countEl.textContent = visible + " / " + total + " settings";
    }
  }

  input.addEventListener("input", filter);
  /* Respect reduced-motion users who tab in: don't steal focus. */
})();
