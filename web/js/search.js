"use strict";

document.addEventListener("DOMContentLoaded", function() {
    // if we already have a favorite IdP, we need to focus on the input search
    // box that becomes visible when the user toggles <details>
    if (null !== document.querySelector("details")) {
        var details = document.querySelector("details");
        details.addEventListener("toggle", function(e) {
            if (this.open) {
                var searchBoxInput = document.querySelector("form#searchBox input");
                searchBoxInput.focus();
            }
        });
    }

    if (null !== document.querySelector("form#searchBox")) {
        var searchBox = document.querySelector("form#searchBox");
        // unhide the search box
        searchBox.style.display = "block";
        searchBox.addEventListener("submit", function(e) {
            // disable default form submit
            e.preventDefault();
        });
        var searchBoxInput = document.querySelector("form#searchBox input");
        searchBoxInput.focus();
        searchBoxInput.addEventListener("keyup", function() {
            var searchFor = this.value.toUpperCase();
            var organizationList = document.querySelectorAll("form#organizationList button");
            var visibleOrganizationCount = 0;
            organizationList.forEach(function(e) {
                var searchIn = e.innerHTML + " " + e.value;
                if (searchIn.toUpperCase().indexOf(searchFor) !== -1) {
                    e.parentElement.style.display = "block";
                    visibleOrganizationCount++;
                } else {
                    e.parentElement.style.display = "none";
                }
            });

            if (0 === visibleOrganizationCount) {
                document.querySelector("span#noResults").style.display = "block";
            } else {
                document.querySelector("span#noResults").style.display = "none";
            }
        });
    }
});