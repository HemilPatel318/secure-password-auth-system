// Reusable show/hide toggle for password fields on auth forms.
document.querySelectorAll("[data-toggle-password]").forEach((button) => {
  button.addEventListener("click", () => {
    const selector = button.getAttribute("data-toggle-password");
    const input = document.querySelector(selector);
    if (!input) return;

    const isPassword = input.getAttribute("type") === "password";
    input.setAttribute("type", isPassword ? "text" : "password");
    button.textContent = isPassword ? "Hide" : "Show";
  });
});
