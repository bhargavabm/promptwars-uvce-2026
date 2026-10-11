(function () {
  "use strict";

  /**
   * Block the form from ever submitting, so no field value can be sent to the
   * server. This page is a demonstration only.
   */
  function preventSubmit(event) {
    event.preventDefault();
  }

  /** Clear every field and reset all checkboxes and inputs to their defaults. */
  function clearForm() {
    var form = document.getElementById("profile-form");
    if (form) {
      form.reset();
    }
  }

  var form = document.getElementById("profile-form");
  if (form) {
    form.addEventListener("submit", preventSubmit);
  }

  var clearButton = document.getElementById("clear-btn");
  if (clearButton) {
    clearButton.addEventListener("click", clearForm);
  }
})();
