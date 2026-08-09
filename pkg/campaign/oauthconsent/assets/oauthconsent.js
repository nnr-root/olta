(function () {
  "use strict";

  function initialize(component) {
    if (component.dataset.oauthReady === "true") return;
    component.dataset.oauthReady = "true";
    var status = component.querySelector("[data-oauth-status]");

    function trigger(decision) {
      if (status) status.textContent = decision === "accept" ? "Permission accepted in this simulation." : "Permission request canceled.";
      component.dispatchEvent(new CustomEvent("olta:oauthconsent:" + decision, {
        bubbles: true,
        detail: { redirectURI: component.dataset.redirectUri || "" }
      }));
    }

    var accept = component.querySelector("[data-oauth-accept]");
    var cancel = component.querySelector("[data-oauth-cancel]");
    if (accept) accept.addEventListener("click", function () { trigger("accept"); });
    if (cancel) cancel.addEventListener("click", function () { trigger("cancel"); });
  }

  function initializeAll(root) {
    if (root.matches && root.matches("[data-oauth-consent]")) initialize(root);
    root.querySelectorAll("[data-oauth-consent]").forEach(initialize);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { initializeAll(document); });
  else initializeAll(document);
  new MutationObserver(function (records) {
    records.forEach(function (record) { record.addedNodes.forEach(function (node) { if (node.nodeType === 1) initializeAll(node); }); });
  }).observe(document.documentElement, { childList: true, subtree: true });
}());
