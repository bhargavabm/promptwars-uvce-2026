(function () {
  "use strict";

  /**
   * Block the demonstration form from ever submitting, so no field value can
   * be sent to the server. This page is a demonstration only.
   */
  function preventSubmit(event) {
    event.preventDefault();
  }

  var form = document.getElementById("profile-form");
  if (form) {
    form.addEventListener("submit", preventSubmit);
  }
})();
