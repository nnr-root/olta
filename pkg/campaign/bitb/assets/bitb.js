(function () {
  "use strict";

  function platformTheme() {
    var platform = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || navigator.userAgent || "";
    if (/linux|x11|ubuntu/i.test(platform)) return "linux";
    if (/mac/i.test(platform)) return "macos";
    return "windows11";
  }

  function emit(frame, name) {
    frame.dispatchEvent(new CustomEvent("olta:bitb:" + name, { bubbles: true }));
  }

  function initialize(frame) {
    if (frame.dataset.bitbReady === "true") return;
    frame.dataset.bitbReady = "true";
    if (frame.dataset.theme === "auto") frame.dataset.resolvedTheme = platformTheme();

    var windowElement = frame.querySelector(".olta-bitb__window");
    var dragHandle = frame.querySelector("[data-bitb-drag-handle]");
    var close = frame.querySelector("[data-bitb-close]");
    var minimize = frame.querySelector("[data-bitb-minimize]");
    var maximize = frame.querySelector("[data-bitb-maximize]");
    var drag = null;

    if (close) close.addEventListener("click", function () { frame.hidden = true; emit(frame, "close"); });
    if (minimize) minimize.addEventListener("click", function () { frame.hidden = true; emit(frame, "minimize"); });
    if (maximize) maximize.addEventListener("click", function () { frame.classList.toggle("olta-bitb--maximized"); windowElement.style.transform = ""; emit(frame, "maximize"); });

    if (!dragHandle || !windowElement) return;
    dragHandle.addEventListener("pointerdown", function (event) {
      if (event.target.closest("button") || frame.classList.contains("olta-bitb--maximized")) return;
      var match = windowElement.style.transform.match(/translate\((-?[\d.]+)px,\s*(-?[\d.]+)px\)/);
      drag = { pointer: event.pointerId, x: event.clientX, y: event.clientY, left: match ? Number(match[1]) : 0, top: match ? Number(match[2]) : 0 };
      dragHandle.setPointerCapture(event.pointerId);
    });
    dragHandle.addEventListener("pointermove", function (event) {
      if (!drag || event.pointerId !== drag.pointer) return;
      var x = drag.left + event.clientX - drag.x;
      var y = drag.top + event.clientY - drag.y;
      windowElement.style.transform = "translate(" + x + "px, " + y + "px)";
    });
    dragHandle.addEventListener("pointerup", function (event) {
      if (drag && event.pointerId === drag.pointer) drag = null;
    });
  }

  function initializeAll(root) {
    if (root.matches && root.matches("[data-bitb-window]")) initialize(root);
    root.querySelectorAll("[data-bitb-window]").forEach(initialize);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { initializeAll(document); });
  else initializeAll(document);
  new MutationObserver(function (records) {
    records.forEach(function (record) { record.addedNodes.forEach(function (node) { if (node.nodeType === 1) initializeAll(node); }); });
  }).observe(document.documentElement, { childList: true, subtree: true });
}());
