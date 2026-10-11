(function () {
  "use strict";

  var messageInput = document.getElementById("message");
  var checkButton = document.getElementById("check-btn");
  var statusBox = document.getElementById("status");
  var statusText = document.getElementById("status-text");
  var resultBox = document.getElementById("result");
  var verdictHeading = document.getElementById("verdict-heading");
  var riskLevel = document.getElementById("risk-level");
  var threatCategory = document.getElementById("threat-category");
  var intent = document.getElementById("intent");
  var rationale = document.getElementById("rationale");
  var triggeredRules = document.getElementById("triggered-rules");

  /** Show a plain status message and hide any previous result. */
  function showStatus(text) {
    resultBox.hidden = true;
    statusText.textContent = text;
    statusBox.hidden = false;
  }

  /** Clear the status and result areas. */
  function clearOutput() {
    resultBox.hidden = true;
    statusBox.hidden = true;
    verdictHeading.textContent = "";
    riskLevel.textContent = "";
    threatCategory.textContent = "";
    intent.textContent = "";
    rationale.textContent = "";
    triggeredRules.textContent = "";
  }

  /** Render a successful verdict payload as plain text and a details table. */
  function renderVerdict(data) {
    verdictHeading.textContent = data.verdict === "approved" ? "Approved" : "Blocked";
    riskLevel.textContent = data.risk_level || "";
    threatCategory.textContent = data.threat_category || "";
    intent.textContent = data.intent || "";
    rationale.textContent = data.rationale || "";

    var rules = Array.isArray(data.triggered_rules) ? data.triggered_rules : [];
    triggeredRules.textContent = rules.length ? rules.join(", ") : "None";

    statusBox.hidden = true;
    resultBox.hidden = false;
  }

  /** Send the message to the firewall API and render the returned verdict. */
  function checkMessage() {
    var text = messageInput.value;

    if (!text || !text.trim()) {
      showStatus("Please type a banking message first.");
      return;
    }

    clearOutput();
    showStatus("Checking message...");
    checkButton.disabled = true;

    fetch("/evaluate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: text })
    })
      .then(function (response) {
        return response
          .json()
          .then(function (body) {
            return { ok: response.ok, status: response.status, body: body };
          })
          .catch(function () {
            return { ok: response.ok, status: response.status, body: null };
          });
      })
      .then(function (result) {
        if (!result.ok) {
          var detail =
            result.body && result.body.error
              ? result.body.error
              : "Server returned status " + result.status + ".";
          showStatus(detail);
          return;
        }
        renderVerdict(result.body);
      })
      .catch(function () {
        showStatus("Could not reach the firewall server. Is it running?");
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
