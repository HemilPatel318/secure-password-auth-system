// Live password checklist used on the registration page.
const passwordInput = document.getElementById("password");
const rules = {
  length: (v) => v.length >= 10,
  upper: (v) => /[A-Z]/.test(v),
  lower: (v) => /[a-z]/.test(v),
  digit: (v) => /\d/.test(v),
  special: (v) => /[^A-Za-z0-9]/.test(v),
};

if (passwordInput) {
  const updateRules = (value) => {
    // Toggle styling for each rule as the user types.
    Object.entries(rules).forEach(([name, check]) => {
      const item = document.querySelector(`[data-rule="${name}"]`);
      if (!item) return;
      const ok = check(value);
      item.classList.remove("good", "bad");
      item.classList.add(ok ? "good" : "bad");
    });
  };

  updateRules(passwordInput.value);
  passwordInput.addEventListener("input", (e) => updateRules(e.target.value));
}
