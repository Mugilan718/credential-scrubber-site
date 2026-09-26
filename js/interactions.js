(function () {
  // Mobile nav toggle (hamburger). Guarded so this file stays safe to load
  // on pages that don't have these elements.
  const navToggle = document.getElementById("navToggle");
  const navLinks = document.getElementById("navLinks");
  if (navToggle && navLinks) {
    navToggle.addEventListener("click", () => {
      const isOpen = navLinks.classList.toggle("open");
      navToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });
    // Close the menu after a link is chosen, so it doesn't stay open
    // covering the section the user just navigated to.
    navLinks.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        navLinks.classList.remove("open");
        navToggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  // Reveal comic panels as they scroll into view
  const panels = document.querySelectorAll(".panel.reveal");
  if (panels.length && "IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry, i) => {
          if (entry.isIntersecting) {
            setTimeout(() => entry.target.classList.add("visible"), i * 80);
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15 }
    );
    panels.forEach((p) => observer.observe(p));
  } else {
    // No IntersectionObserver support - just show them immediately
    panels.forEach((p) => p.classList.add("visible"));
  }

  // Subtle mouse-follow parallax on the hero glow, for a "responsive to touch" feel.
  // Skipped entirely for reduced-motion preference and on touch-only devices
  // (no meaningful mouse position there anyway).
  const heroGlow = document.querySelector(".hero-glow");
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const isTouchOnly = window.matchMedia("(hover: none)").matches;

  if (heroGlow && !prefersReducedMotion && !isTouchOnly) {
    document.addEventListener("mousemove", (e) => {
      const xPct = (e.clientX / window.innerWidth - 0.5) * 2;
      const yPct = (e.clientY / window.innerHeight - 0.5) * 2;
      heroGlow.style.transform = `translate(calc(-50% + ${xPct * 24}px), calc(-50% + ${yPct * 24}px))`;
    });
  }
})();
