const searchInput = document.getElementById('searchInput');
const cards = [...document.querySelectorAll('.article-card')];
const emptyState = document.getElementById('emptyState');
const themeToggle = document.getElementById('themeToggle');

// Search is only present on the homepage, so don't assume it exists on article pages.
if (searchInput) {
  searchInput.addEventListener('input', () => {
    const query = searchInput.value.trim().toLowerCase();
    let visible = 0;

    cards.forEach((card) => {
      const searchableText = [
        card.dataset.title,
        card.dataset.tags,
        card.dataset.category,
        card.textContent
      ].join(' ').toLowerCase();

      const match = searchableText.includes(query);
      card.hidden = !match;
      if (match) visible += 1;
    });

    if (emptyState) emptyState.hidden = visible !== 0;
  });
}

// Persist the reader's theme preference locally.
const savedTheme = localStorage.getItem('science-blog-theme');
if (savedTheme === 'dark') document.body.classList.add('dark');

function updateThemeIcon() {
  if (!themeToggle) return;
  const dark = document.body.classList.contains('dark');
  themeToggle.textContent = dark ? '☀' : '☾';
  themeToggle.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
}

updateThemeIcon();

themeToggle?.addEventListener('click', () => {
  document.body.classList.toggle('dark');
  localStorage.setItem('science-blog-theme', document.body.classList.contains('dark') ? 'dark' : 'light');
  updateThemeIcon();
});
