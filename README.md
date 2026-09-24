# Syntax & Substance — Maintainable Science Blog

A minimal static blog for mathematics, physics, computer science, engineering, electronics, and technical writing.

The site uses:

- Markdown for posts
- Eleventy for generating HTML
- GitHub as the source of truth
- Cloudflare for automatic deployment
- MathJax for LaTeX mathematics
- Plain CSS and JavaScript for the frontend

## Add a new post

Copy `POST-TEMPLATE.md` into `posts/` and rename it. For example:

```text
posts/my-new-article.md
```

Fill in the front matter, then write normal Markdown.

Every Markdown file in `posts/` is automatically discovered and added to the homepage and gets its own URL.

## Math

Inline math:

```text
$F=ma$
```

Display math:

```text
$$
F = ma
$$
```

## Images

Put images in:

```text
src/assets/
```

They are copied to the public `/assets/` directory.

## Local development

Install dependencies:

```powershell
npm install
```

Start a local development server:

```powershell
npm run dev
```

Create a production build:

```powershell
npm run build
```

The generated site appears in `_site/`. Do not edit `_site/` manually.

## Publish

```powershell
git add .
git commit -m "Add new science article"
git push
```

The connected Cloudflare deployment rebuilds from the GitHub `main` branch.
