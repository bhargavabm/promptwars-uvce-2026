(function () {
  "use strict";

  var messageInput = document.getElementById("message");
  var checkButton = document.getElementById("check-btn");
  var statusBox = document.getElementById("status");
  var badge = document.getElementById("badge");
  var statusText = document.getElementById("status-text");
  var resultBox = document.getElementById("result");
  var riskLevel = document.getElementById("risk-level");
  var threatCategory = document.getElementById("threat-category");
  var intent = document.getElementById("intent");
  var rationale = document.getElementById("rationale");
  var triggeredRules = document.getElementById("triggered-rules");
  var rawJson = document.getElementById("raw-json");

  /** Set the badge and status line. */
  function showStatus(kind, text) {
    badge.textContent = kind === "approved" ? "Approved" : kind === "blocked" ? "Blocked" : "Error";
    badge.className = "badge " + kind;
    statusText.textContent = text;
    statusBox.hidden = false;
  }

  /** Clear and hide the previous result. */
  function clearResult() {
    resultBox.hidden = true;
    statusBox.hidden = true;
    riskLevel.textContent = "";
    threatCategory.textContent = "";
    intent.textContent = "";
    rationale.textContent = "";
    triggeredRules.textContent = "";
    rawJson.textContent = "";
  }

  /** Render a successful verdict payload. */
  function renderVerdict(data) {
    riskLevel.textContent = data.risk_level || "";
    threatCategory.textContent = data.threat_category || "";
    intent.textContent = data.intent || "";
    rationale.textContent = data.rationale || "";

    var rules = Array.isArray(data.triggered_rules) ? data.triggered_rules : [];
    triggeredRules.textContent = rules.length ? rules.join(", ") : "None";

    rawJson.textContent = JSON.stringify(data, null, 2);
    resultBox.hidden = false;

    if (data.verdict === "approved") {
      showStatus("approved", "This request is safe to proceed.");
    } else {
      showStatus("blocked", "This request was blocked by the firewall.");
    }
  }

  /** Show a readable error without leaking internals. */
  function showError(message) {
    clearResult();
    showStatus("error", message);
  }

  /** Send the message to the firewall API and render the verdict. */
  function checkMessage() {
    var text = messageInput.value;

    if (!text || !text.trim()) {
      showError("Please type a banking message first.");
      return;
    }

    clearResult();
    showStatus("error", "Checking message...");
    checkButton.disabled = true;

    fetch("/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text })
    })
      .then(function (response) {
        return response.json().then(function (body) {
          return { ok: response.ok, status: response.status, body: body };
        });
      })
      .then(function (result) {
        if (result.status === 401) {
          window.location.href = "/login";
          return;
        }
        if (!result.ok) {
          var detail =
            result.body && result.body.error
              ? result.body.error
              : "Server returned status " + result.status + ".";
          showError(detail);
          return;
        }
        renderVerdict(result.body);
      })
      .catch(function () {
        showError("Could not reach the firewall server. Is it running?");
      })
      .finally(function () {
        checkButton.disabled = false;
      });
  }

  checkButton.addEventListener("click", checkMessage);

  var exampleButtons = document.querySelectorAll(".btn-example");
  Array.prototype.forEach.call(exampleButtons, function (button) {
    button.addEventListener("click", function () {
      messageInput.value = button.getAttribute("data-message") || "";
      messageInput.focus();
    });
  });
})();
