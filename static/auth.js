(function () {
  "use strict";

  var STORAGE_KEY = "bankism_signin_prompt_seen";
  var MODAL_DELAY_MS = 3000;

  var modal = document.getElementById("signin-modal");
  var closeButton = document.getElementById("signin-close");
  var skipLink = document.getElementById("signin-skip");
  var googleButton = document.getElementById("google-btn");
  var googleMessage = document.getElementById("google-message");
  var phoneInput = document.getElementById("phone-input");
  var codeInput = document.getElementById("code-input");
  var sendButton = document.getElementById("phone-send");
  var verifyButton = document.getElementById("phone-verify");
  var phoneMessage = document.getElementById("phone-message");
  var navAuth = document.getElementById("nav-auth");

  var state = { clientId: null, signedIn: false };
  var lastFocused = null;

  /** Read a value from sessionStorage, returning null on any failure. */
  function readSessionStorage(key) {
    try {
      return window.sessionStorage.getItem(key);
    } catch (error) {
      return null;
    }
  }

  /** Write a value to sessionStorage, ignoring any failure. */
  function writeSessionStorage(key, value) {
    try {
      window.sessionStorage.setItem(key, value);
    } catch (error) {
      /* Storage may be unavailable; the modal simply may show again. */
    }
  }

  /** Show or clear a message element with the given text. */
  function setMessage(element, text) {
    if (!element) {
      return;
    }
    element.textContent = text || "";
    element.hidden = !text;
  }

  /** Enable or disable a button while a request is in flight. */
  function setBusy(button, busy) {
    if (button) {
      button.disabled = busy;
    }
  }

  /**
   * Send a request and parse a JSON body, resolving to
   * {ok, status, body} or rejecting with a readable Error.
   */
  function requestJson(url, options) {
    return fetch(url, options || {})
      .then(function (response) {
        return response
          .json()
          .catch(function () {
            return null;
          })
          .then(function (body) {
            return { ok: response.ok, status: response.status, body: body };
          });
      })
      .catch(function () {
        throw new Error("Network error. Please check your connection and try again.");
      });
  }

  /** Return the focusable elements inside the modal. */
  function getFocusable() {
    if (!modal) {
      return [];
    }
    var nodes = modal.querySelectorAll(
      "button, a[href], input, select, textarea, [tabindex]:not([tabindex='-1'])"
    );
    return Array.prototype.filter.call(nodes, function (node) {
      return !node.disabled && node.offsetParent !== null;
    });
  }

  /** Trap keyboard focus and handle Escape while the modal is open. */
  function onKeydown(event) {
    if (event.key === "Escape") {
      closeModal();
      return;
    }
    if (event.key !== "Tab") {
      return;
    }
    var focusable = getFocusable();
    if (focusable.length === 0) {
      return;
    }
    var first = focusable[0];
    var last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  /** Open the modal and move focus inside it. */
  function openModal() {
    if (!modal) {
      return;
    }
    writeSessionStorage(STORAGE_KEY, "1");
    lastFocused = document.activeElement;
    modal.hidden = false;
    document.body.classList.add("modal-open");
    document.addEventListener("keydown", onKeydown);
    var focusable = getFocusable();
    if (focusable.length) {
      focusable[0].focus();
    }
  }

  /** Close the modal and restore focus to the previously active element. */
  function closeModal() {
    if (!modal) {
      return;
    }
    modal.hidden = true;
    document.body.classList.remove("modal-open");
    document.removeEventListener("keydown", onKeydown);
    if (lastFocused && typeof lastFocused.focus === "function") {
      lastFocused.focus();
    }
  }

  /** Show the modal once per browser session unless the visitor is signed in. */
  function armModal() {
    if (!modal) {
      return;
    }
    if (readSessionStorage(STORAGE_KEY)) {
      return;
    }
    window.setTimeout(function () {
      if (!state.signedIn) {
        openModal();
      }
    }, MODAL_DELAY_MS);
  }

  /** Render the signed-in navigation state and a sign-out control. */
  function renderSignedIn(payload) {
    state.signedIn = true;
    if (!navAuth) {
      return;
    }
    navAuth.textContent = "";
    var name = document.createElement("span");
    name.className = "nav-user";
    name.textContent = payload && payload.name ? payload.name : "Signed in";
    var signOut = document.createElement("button");
    signOut.type = "button";
    signOut.className = "nav-signout";
    signOut.textContent = "Sign out";
    signOut.addEventListener("click", onSignOut);
    navAuth.appendChild(name);
    navAuth.appendChild(signOut);
  }

  /** Clear the signed-in navigation state. */
  function renderSignedOut() {
    state.signedIn = false;
    if (navAuth) {
      navAuth.textContent = "";
    }
  }

  /** Sign the visitor out and update the navigation bar. */
  function onSignOut() {
    requestJson("/auth/logout", { method: "POST" })
      .then(function () {
        renderSignedOut();
      })
      .catch(function () {
        renderSignedOut();
      });
  }

  /** Load the public configuration and prepare Google Identity Services. */
  function loadConfig() {
    requestJson("/config")
      .then(function (result) {
        if (result.ok && result.body) {
          state.clientId = result.body.google_client_id || null;
        }
        initGoogle();
      })
      .catch(function () {
        state.clientId = null;
        initGoogle();
      });
  }

  /** Initialize Google Identity Services when a client ID is configured. */
  function initGoogle() {
    if (!state.clientId) {
      return;
    }
    if (!(window.google && window.google.accounts && window.google.accounts.id)) {
      return;
    }
    window.google.accounts.id.initialize({
      client_id: state.clientId,
      callback: onGoogleCredential
    });
  }

  /** Start the Google sign-in flow, or explain that it is not configured. */
  function onGoogleClick() {
    setMessage(googleMessage, "");
    if (!state.clientId) {
      setMessage(googleMessage, "Google sign-in is not configured for this server.");
      return;
    }
    if (window.google && window.google.accounts && window.google.accounts.id) {
      window.google.accounts.id.prompt();
    } else {
      setMessage(googleMessage, "Google sign-in is not available right now.");
    }
  }

  /** Send the Google ID token to the server and sign in on success. */
  function onGoogleCredential(response) {
    if (!response || !response.credential) {
      return;
    }
    setBusy(googleButton, true);
    requestJson("/auth/google", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: response.credential })
    })
      .then(function (result) {
        if (result.ok && result.body && result.body.signed_in) {
          renderSignedIn(result.body);
          closeModal();
        } else {
          setMessage(
            googleMessage,
            (result.body && result.body.error) || "Google sign-in could not be verified."
          );
        }
      })
      .catch(function (error) {
        setMessage(googleMessage, error.message);
      })
      .finally(function () {
        setBusy(googleButton, false);
      });
  }

  /** Request a demonstration verification code for the entered phone number. */
  function onSendCode() {
    setMessage(phoneMessage, "");
    var phone = phoneInput ? phoneInput.value.trim() : "";
    setBusy(sendButton, true);
    requestJson("/auth/phone/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone: phone })
    })
      .then(function (result) {
        if (result.ok) {
          setMessage(phoneMessage, "A demonstration code is ready. Enter 123456 to continue.");
        } else {
          setMessage(phoneMessage, (result.body && result.body.error) || "Could not send a code.");
        }
      })
      .catch(function (error) {
        setMessage(phoneMessage, error.message);
      })
      .finally(function () {
        setBusy(sendButton, false);
      });
  }

  /** Verify the demonstration code and sign in on success. */
  function onVerifyCode() {
    setMessage(phoneMessage, "");
    var phone = phoneInput ? phoneInput.value.trim() : "";
    var code = codeInput ? codeInput.value.trim() : "";
    setBusy(verifyButton, true);
    requestJson("/auth/phone/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone: phone, code: code })
    })
      .then(function (result) {
        if (result.ok && result.body && result.body.signed_in) {
          renderSignedIn(result.body);
          closeModal();
        } else {
          setMessage(
            phoneMessage,
            (result.body && result.body.error) || "Invalid verification code."
          );
        }
      })
      .catch(function (error) {
        setMessage(phoneMessage, error.message);
      })
      .finally(function () {
        setBusy(verifyButton, false);
      });
  }

  /** Restore sign-in state on load and arm the modal when signed out. */
  function restoreSession() {
    requestJson("/auth/session")
      .then(function (result) {
        if (result.ok && result.body && result.body.signed_in) {
          renderSignedIn(result.body);
        } else {
          armModal();
        }
      })
      .catch(function () {
        armModal();
      });
  }

  if (modal) {
    if (closeButton) {
      closeButton.addEventListener("click", closeModal);
    }
    if (skipLink) {
      skipLink.addEventListener("click", function (event) {
        event.preventDefault();
        writeSessionStorage(STORAGE_KEY, "1");
        closeModal();
      });
    }
    if (googleButton) {
      googleButton.addEventListener("click", onGoogleClick);
    }
    if (sendButton) {
      sendButton.addEventListener("click", onSendCode);
    }
    if (verifyButton) {
      verifyButton.addEventListener("click", onVerifyCode);
    }

    loadConfig();
    restoreSession();
  }
})();
