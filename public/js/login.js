/**
 * 🌬️ AIR Monitor Login Script
 * Version: 3.0 (Stable)
 * Author: The Real Soske (Kaine Sama)
 * 
 * Handles login + auto-registration for AIR users.
 * Fully synced with AIR Hybrid Server v3.0 backend.
 */

const form = document.getElementById("loginForm");
const msg = document.getElementById("message");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  msg.textContent = "";
  msg.style.color = "#aaa";

  const username = document.getElementById("username").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();

  if (!email || !password) {
    msg.style.color = "#f85149";
    msg.textContent = "❌ Please fill in all fields.";
    return;
  }

  try {
    // Step 1: Try to log in
    let res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    // Step 2: Auto-register if not found
    if (res.status === 401) {
      msg.textContent = "⚙️ Account not found — registering...";
      await fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password })
      });
      res = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });
    }

    // Step 3: Safely handle the response
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      throw new Error("Server returned HTML instead of JSON. Check backend.");
    }

    if (!res.ok) throw new Error(data.message || "Login failed.");

    // Step 4: Save session data
    localStorage.setItem("AIR_TOKEN", data.token);
    localStorage.setItem("AIR_USER", data.username);

    // Step 5: Confirm success
    msg.style.color = "#3fb950";
    msg.textContent = "✅ Login successful! Redirecting...";
    setTimeout(() => window.location.href = "/dashboard.html", 1200);
  } catch (err) {
    console.error("Login Error:", err);
    msg.style.color = "#f85149";
    msg.textContent = "❌ " + err.message;
  }
});

// Optional: quick token check
window.addEventListener("load", () => {
  const token = localStorage.getItem("AIR_TOKEN");
  if (token) {
    msg.style.color = "#3fb950";
    msg.textContent = "🔐 Already logged in. Redirecting...";
    setTimeout(() => window.location.href = "/dashboard.html", 1000);
  }
});
