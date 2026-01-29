register.js
function toggleForm() {
    let login = document.getElementById("loginForm");
    let signup = document.getElementById("signupForm");
    let title = document.getElementById("title");
    let switchText = document.getElementById("switchText");
    let link = document.querySelector(".switch a");

    if (login.classList.contains("hidden")) {
        login.classList.remove("hidden");
        signup.classList.add("hidden");
        title.innerText = "Log in";
        switchText.innerText = "Don't have an account?";
        link.innerText = "Sign up";
    } else {
        login.classList.add("hidden");
        signup.classList.remove("hidden");
        title.innerText = "Sign up";
        switchText.innerText = "Already have an account?";
        link.innerText = "Log in";
    }
}
