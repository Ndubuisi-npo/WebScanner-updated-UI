document.getElementById("scan-form").addEventListener("submit", function(event) {
    event.preventDefault();
    
    let url = document.getElementById("url").value;
    let checkboxes = document.querySelectorAll('input[name="checks"]:checked');
    let selectedChecks = Array.from(checkboxes).map(cb => cb.value);

    if (!url) {
        alert("Please enter a target URL.");
        return;
    }

    let resultsDiv = document.getElementById("results");
    
    // Show scanning message and animation
    resultsDiv.innerHTML = `
        <div class="scanning-container">
            <h2>Scanning, Please wait...</h2>
            <div class="loader">
                <span></span>
                <span></span>               
                <span></span>
                <span></span>
                <span></span>
                <span></span>
            </div>
        </div>
    `;

    fetch("/scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: url, checks: selectedChecks })
    })
    .then(response => response.json())
    .then(data => {
        let resultHTML = "<h2>Scan Results:</h2>";
        
        for (let key in data) {
            resultHTML += `<h3>${key}:</h3><p>${JSON.stringify(data[key])}</p>`;
        }

        // Show results and remove loading animation
        resultsDiv.innerHTML = resultHTML;
    })
    .catch(error => {
        resultsDiv.innerHTML = "<p style='color: red;'>Error: Could not complete the scan.</p>";
        console.error("Error:", error);
    });
});


function toggleMenu() {
    let menu = document.getElementById("menu");
    if (menu.style.left === "0px") {
        menu.style.left = "-250px"; // Slide out
    } else {
        menu.style.left = "0px"; // Slide in
    }
}
