// Shared utility functions for bouncer admin UI.

// DOM helper: shorthand for document.getElementById.
function $(id) {
  return document.getElementById(id);
}

// HTML escape a string to prevent XSS.
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}

// Format ISO timestamp to locale string, or return empty if falsy.
function fmtTime(s) {
  if (!s) return "";
  try {
    return new Date(s).toLocaleString();
  } catch (_) {
    return s;
  }
}

// Fetch with automatic JSON parsing. Returns {ok, status, body, raw}.
// body is parsed JSON if response had content; raw is unparsed text.
async function fetchJSON(method, url, body) {
  const opts = { method, headers: { "content-type": "application/json" } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const resp = await fetch(url, opts);
  const text = await resp.text();
  let parsed = null;
  if (text) {
    try { parsed = JSON.parse(text); } catch (_) { parsed = text; }
  }
  return { ok: resp.ok, status: resp.status, body: parsed, raw: text };
}

// Copy button delegation: button[data-copy-target="foo"] copies element[data-snippet="foo"].
// Usage: setupCopyButton("[data-copy-target]", "[data-snippet]")
function setupCopyButton(btnSelector, sourceSelector) {
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest(btnSelector);
    if (!btn) return;
    const attrName = sourceSelector.slice(1, -1); // "[data-snippet]" → "data-snippet"
    const source = document.querySelector(`${sourceSelector}[${attrName}="${btn.dataset.copyTarget}"]`);
    if (!source) return;
    try {
      await navigator.clipboard.writeText(source.textContent);
      const orig = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = orig; }, 1200);
    } catch (_) {}
  });
}

// Generic tab switcher: on click of [data-tab], show/hide panes.
// tabs: selector for tab buttons (e.g. "[data-tab]")
// panes: selector for pane divs (e.g. "[data-pane]")
// attrTab: attribute name on tab button (default "data-tab")
// attrPane: attribute name on pane div (default "data-pane")
function setupTabs(tabs, panes, attrTab = "data-tab", attrPane = "data-pane") {
  const tabEls = document.querySelectorAll(tabs);
  const paneEls = document.querySelectorAll(panes);

  document.addEventListener("click", (e) => {
    const tab = e.target.closest(tabs);
    if (!tab) return;
    const which = tab.getAttribute(attrTab);
    if (!which) return;

    tabEls.forEach(t => {
      t.classList.toggle("active", t.getAttribute(attrTab) === which);
    });
    paneEls.forEach(p => {
      p.classList.toggle("active", p.getAttribute(attrPane) === which);
    });
  });
}

// Generic multiselect dropdown: checkboxes synced to a hidden select.
// Returns {populate, updateSelection} functions.
//
// Usage:
//   const {populate, updateSelection} = setupMultiselect(host, {
//     toggleBtn: <element>,
//     dropdown: <element>,
//     selectEl: <element>,
//     optionClassName: "my-option",
//     emptyLabel: "any",
//     onUpdate: () => { /* refresh or other callback */ }
//   });
//   populate(["api1", "api2"], currentSelections);
function setupMultiselect(host, config) {
  if (!host) return;

  const {
    toggleBtn,
    dropdown,
    selectEl,
    optionClassName = "multiselect-option",
    emptyLabel = "any",
    onUpdate
  } = config;

  const toggleLabel = toggleBtn?.querySelector(".multiselect-toggle-label");

  if (!toggleBtn || !dropdown || !selectEl) {
    console.warn("setupMultiselect: missing elements", { toggleBtn, dropdown, selectEl });
    return;
  }

  selectEl.multiple = true;

  // Close dropdown when clicking outside
  document.addEventListener("click", (e) => {
    if (!toggleBtn.contains(e.target) && !dropdown.contains(e.target)) {
      toggleBtn.classList.remove("open");
      dropdown.classList.remove("open");
    }
  });

  // Toggle dropdown on button click
  toggleBtn.addEventListener("click", (e) => {
    e.preventDefault();
    toggleBtn.classList.toggle("open");
    dropdown.classList.toggle("open");
  });

  // Update label and synced select to match current checkbox state
  function syncSelection() {
    const checkboxes = Array.from(dropdown.querySelectorAll("input[type='checkbox']"));

    // Sync checkboxes to hidden select
    for (const checkbox of checkboxes) {
      const opt = Array.from(selectEl.options).find(o => o.value === checkbox.value);
      if (opt) opt.selected = checkbox.checked;
    }

    // Update toggle label
    if (toggleLabel) {
      const selected = checkboxes.filter(cb => cb.checked).length;
      if (selected === 0) {
        toggleLabel.textContent = emptyLabel;
        toggleLabel.classList.remove("has-selection");
      } else if (selected === 1) {
        const name = checkboxes.find(cb => cb.checked).value;
        toggleLabel.textContent = name;
        toggleLabel.classList.add("has-selection");
      } else {
        toggleLabel.textContent = `${selected} selected`;
        toggleLabel.classList.add("has-selection");
      }
    }
  }

  // Called when user changes a checkbox; syncs state and triggers callback
  function updateSelection() {
    syncSelection();
    if (onUpdate) onUpdate();
  }

  // Populate dropdown with options from array (or array of objects with .name property)
  function populate(items, currentSelections = []) {
    // Preserve current selection before clearing
    const preserved = currentSelections.length > 0
      ? currentSelections
      : Array.from(selectEl.selectedOptions).map(o => o.value);

    // Clear existing options and dropdown items
    selectEl.innerHTML = '';
    dropdown.innerHTML = '';

    // Add empty option
    const emptyOpt = document.createElement("option");
    emptyOpt.value = "";
    emptyOpt.textContent = emptyLabel;
    selectEl.appendChild(emptyOpt);

    // Add each item
    for (const item of items) {
      // Get value and label (support both strings and objects with .name)
      const value = typeof item === 'string' ? item : item.name;
      const label = typeof item === 'string' ? item : item.name;

      // Add to hidden select
      const opt = document.createElement("option");
      opt.value = value;
      opt.textContent = label;
      selectEl.appendChild(opt);

      // Add checkbox to dropdown
      const div = document.createElement("div");
      div.className = optionClassName;
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = value;
      checkbox.checked = preserved.includes(value);
      checkbox.addEventListener("change", updateSelection);
      div.appendChild(checkbox);

      const labelEl = document.createElement("label");
      labelEl.textContent = label;
      labelEl.style.cursor = "pointer";
      labelEl.style.margin = "0";
      labelEl.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        checkbox.checked = !checkbox.checked;
        checkbox.dispatchEvent(new Event("change", { bubbles: true }));
      });
      div.appendChild(labelEl);
      dropdown.appendChild(div);
    }

    // Sync the UI without triggering the callback
    syncSelection();
  }

  return { populate, updateSelection };
}

// Fetch JSON from a URL, render into a container on success or error.
// fn(data) is called to render; errors default to "Failed to load: {message}".
async function fetchAndRender(url, container, fn, options = {}) {
  const { errorClass = "err", errorPrefix = "Failed to load" } = options;
  try {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    fn(data, container);
  } catch (err) {
    container.innerHTML = `<div class="${errorClass}">${esc(errorPrefix)}: ${esc(err.message)}</div>`;
  }
}
