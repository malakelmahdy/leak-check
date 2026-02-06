// Mobile nav toggle
const navToggle = document.querySelector(".nav-toggle");
const navLinks = document.querySelector(".nav-links");
navToggle.addEventListener("click", () => {
    navLinks.classList.toggle("open");
    document.querySelector(".hamburger").classList.toggle("open");
});

// Close mobile nav when a link is clicked
document.querySelectorAll(".nav-links a").forEach((link) => {
    link.addEventListener("click", (e) => {
        e.preventDefault();
        const target = document.querySelector(link.getAttribute("href"));
        // close mobile nav if open
        if (navLinks.classList.contains("open")) navLinks.classList.remove("open");

        // smooth scroll with offset for fixed navbar
        const yOffset = -64;
        const y = target.getBoundingClientRect().top + window.pageYOffset + yOffset;
        window.scrollTo({ top: y, behavior: "smooth" });
    });
});

// Navbar background change on scroll
const navbar = document.querySelector(".navbar");
window.addEventListener("scroll", () => {
    if (window.scrollY > 80) navbar.style.backgroundColor = "rgba(11,12,16,0.95)";
    else navbar.style.backgroundColor = "rgba(11,12,16,0.85)";
});

// Simulated form submission (prototype behavior)
const contactForm = document.getElementById("contactForm");
const clearBtn = document.getElementById("clearForm");

contactForm.addEventListener("submit", (e) => {
    e.preventDefault();
    // gather data
    const data = new FormData(contactForm);
    const payload = Object.fromEntries(data.entries());

    // show a friendly simulated response (no network)
    alert(`Thanks, ${payload.name || "there"}! 🎉\nWe received your request and will contact ${payload.email || "you"} shortly.`);

    // simple visual feedback (reset)
    contactForm.reset();
});

clearBtn.addEventListener("click", () => contactForm.reset());
// Highlight active nav link
  const currentPage = window.location.pathname.split("/").pop();
  document.querySelectorAll("nav ul li a").forEach(link => {
    if (link.getAttribute("href") === currentPage) {
      link.classList.add("active");
    }
  });