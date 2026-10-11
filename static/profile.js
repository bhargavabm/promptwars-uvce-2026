(function () {
  "use strict";

  /** Set the text content of an element by id when it exists. */
  function setText(id, value) {
    var element = document.getElementById(id);
    if (element) {
      element.textContent = value === null || value === undefined ? "" : String(value);
    }
  }

  /** Render the recent activity list from the loaded profile data. */
  function renderActivity(items) {
    var list = document.getElementById("activity-list");
    if (!list) {
      return;
    }

    list.textContent = "";

    if (!Array.isArray(items) || items.length === 0) {
      var empty = document.createElement("li");
      empty.className = "activity-item activity-empty";
      empty.textContent = "No recent activity.";
      list.appendChild(empty);
      return;
    }

    items.forEach(function (item) {
      var row = document.createElement("li");
      row.className = "activity-item";

      var description = document.createElement("span");
      description.className = "activity-desc";
      description.textContent = item.description || "";

      var amount = document.createElement("span");
      amount.className = "activity-amount";
      amount.textContent = item.amount || "";

      var date = document.createElement("span");
      date.className = "activity-date";
      date.textContent = item.date || "";

      row.appendChild(description);
      row.appendChild(amount);
      row.appendChild(date);
      list.appendChild(row);
    });
  }

  fetch("/static/data/profile.json")
    .then(function (response) {
      if (!response.ok) {
        throw new Error("Failed to load profile data");
      }
      return response.json();
    })
    .then(function (data) {
      setText("profile-initials", data.initials || "");
      setText("profile-name", data.name || "");
      setText("profile-account-type", data.accountType || "");
      setText("profile-account-number", data.accountNumber || "");
      renderActivity(data.recentActivity);
    })
    .catch(function () {
      setText("profile-name", "Profile data unavailable");
      setText("profile-account-type", "");
      setText("profile-account-number", "");
    });
})();
