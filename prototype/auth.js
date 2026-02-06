document.addEventListener("DOMContentLoaded", () => {
    const signupForm = document.getElementById("signupForm");
    const loginForm = document.getElementById("loginForm");

    // Handle Signup
    if (signupForm) {
        signupForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const name = document.getElementById("name").value;
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;
            const confirmPassword = document.getElementById("confirmPassword").value;

            if (password !== confirmPassword) {
                alert("Passwords do not match!");
                return;
            }

            try {
                const response = await fetch("http://localhost:3000/signup", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ name, email, password }),
                });

                const data = await response.json();

                if (response.ok) {
                    alert("OTP sent! Please check your email (and server console for test link).");
                    // Hide signup form, show OTP form
                    signupForm.style.display = "none";
                    document.getElementById("otpSection").style.display = "block";
                    // Store email for verification step
                    localStorage.setItem("pendingEmail", email);
                    
                    if (data.preview) {
                        console.log("Check email here:", data.preview);
                    }
                } else {
                    alert(data.error || "Signup failed.");
                }
            } catch (error) {
                console.error("Error:", error);
                alert("An error occurred. Please try again.");
            }
        });

        // Handle OTP Verification
        const otpForm = document.getElementById("otpForm");
        if (otpForm) {
            otpForm.addEventListener("submit", async (e) => {
                e.preventDefault();
                const otp = document.getElementById("otpInput").value;
                const email = localStorage.getItem("pendingEmail");

                try {
                    const response = await fetch("http://localhost:3000/verify-otp", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ email, otp }),
                    });

                    const data = await response.json();

                    if (response.ok) {
                        alert("Account verified! Please log in.");
                        localStorage.removeItem("pendingEmail");
                        window.location.href = "login.html";
                    } else {
                        alert(data.error || "Verification failed.");
                    }
                } catch (error) {
                    console.error("Error:", error);
                    alert("An error occurred. Please try again.");
                }
            });
        }
    }

    // Handle Login
    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;

            try {
                const response = await fetch("http://localhost:3000/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, password }),
                });

                const data = await response.json();

                if (response.ok) {
                    // Store user info (in a real app, store a token)
                    localStorage.setItem("user", JSON.stringify(data.user));
                    alert(`Welcome back, ${data.user.name}!`);
                    window.location.href = "index.html";
                } else {
                    alert(data.error || "Login failed eeeeeeeeee.");
                }
            } catch (error) {
                console.error("Error:", error);
                alert("An error occurred. Please try again.");
            }
        });
    }
});
