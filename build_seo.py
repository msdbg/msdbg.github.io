import html
import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import quote, unquote

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent
SITE = "https://blog.offensive32.com"
POSTS_JSON = ROOT / "posts.json"
POSTS_DIR = ROOT / "posts"
OUT_P = ROOT / "p"


def slugify(legacy_id: str) -> str:
    s = legacy_id.replace("&", "")
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "post"


def fix_date(d: str) -> str:
    
    m = re.match(r"^\s*(\d{4})-(\d{1,2})-(\d{1,2})\s*$", str(d))
    if m:
        y, mo, da = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return f"{y:04d}-{mo:02d}-{da:02d}"
    return str(d)


def md_to_html(md_text: str, assets_dir: str | None) -> str:
    md = MarkdownIt("commonmark")
    raw = md.render(md_text)
    if not assets_dir:
        return raw

    def repl(m):
        prefix, src, suffix = m.group(1), m.group(2), m.group(3)
        if src.startswith(("http://", "https://", "data:", "/")):
            return m.group(0)

        enc = "/".join(quote(unquote(part), safe="") for part in src.split("/"))
        return f'{prefix}/assets/posts/{quote(assets_dir)}/{enc}{suffix}'

    return re.sub(r'(<img[^>]*?\ssrc=")([^"]+)(")', repl, raw)


POST_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title_esc} | Offensive32 Labs Blog</title>
<meta name="description" content="{excerpt_esc}">
<meta name="robots" content="index, follow, max-image-preview:large">
<meta name="author" content="{author_esc}">
<link rel="canonical" href="{canonical}">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Offensive32 Labs Blog">
<meta property="og:title" content="{title_esc}">
<meta property="og:description" content="{excerpt_esc}">
<meta property="og:url" content="{canonical}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{title_esc}">
<meta name="twitter:description" content="{excerpt_esc}">
<meta name="o32:legacy-id" content="{legacy_id_esc}">
<meta name="theme-color" content="#0a0a0a">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%230a0a0a'/%3E%3Ctext x='6' y='22' font-family='monospace' font-size='16' fill='%2300fff9'%3E%3E_%3C/text%3E%3C/svg%3E">
<link rel="stylesheet" href="/style.css">
<script type="application/ld+json">
{jsonld}
</script>
</head>
<body>
<div class="scanline"></div>
<div class="noise"></div>
<header class="header">
<div class="glitch" data-text="[ OFFENSIVE32_LABS_BLOGSITE ]">[ OFFENSIVE32_LABS_BLOGSITE ]</div>
<div class="subtitle">// unauthorized access logged</div>
</header>
<main class="terminal">
<p style="margin:1rem 0"><a href="/">&larr; back to terminal</a> &nbsp;|&nbsp; <a href="/#post/{legacy_id_url}">open in terminal view</a></p>
<article class="post-article">
<h1>{title_esc}</h1>
<p class="post-meta">// DECRYPTED: {date_iso} | AUTHOR: {author_esc} | LEGACY: #post/{legacy_id_esc}</p>
<div class="post-tags">{tags_html}</div>
<div class="post-body">{body_html}</div>
<hr>
<p>Share (legacy URL, never breaks): <code>https://blog.offensive32.com/#post/{legacy_id_url}</code><br>
Canonical (indexable): <code>{canonical}</code></p>
<p><a href="/">&larr; back to terminal</a></p>
</article>
</main>
<footer class="footer">
<div class="footer-left"><span class="blink">●</span> CONNECTION_NOT_SECURE</div>
<div class="footer-right"><span>blog.offensive32.com</span></div>
</footer>
</body>
</html>
"""


def main() -> None:
    data = json.loads(POSTS_JSON.read_text(encoding="utf-8"))
    posts = data["posts"]
    OUT_P.mkdir(exist_ok=True)

    mapping: dict[str, str] = {}
    sitemap_urls: list[tuple[str, str]] = [(f"{SITE}/", date.today().isoformat())]

    for p in posts:
        legacy_id: str = p["id"]
        slug = slugify(legacy_id)
        mapping[legacy_id] = slug
        date_iso = fix_date(p.get("date", ""))
        title = p.get("title", slug)
        excerpt = p.get("excerpt") or "Offensive32 Security Research Blog"
        author = p.get("author") or "msdbg"
        tags = p.get("tags") or []
        md_path = POSTS_DIR / p["file"]
        md_text = md_path.read_text(encoding="utf-8") if md_path.exists() else f"# {title}\n\n{excerpt}\n"
        body_html = md_to_html(md_text, p.get("assetsDir"))
        canonical = f"{SITE}/p/{slug}/"
        legacy_id_url = quote(legacy_id, safe="")
        tags_html = "".join(f'<span class="tag">{html.escape(t)}</span>' for t in tags)
        jsonld = json.dumps(
            {
                "@context": "https://schema.org",
                "@type": "BlogPosting",
                "headline": title,
                "description": excerpt,
                "datePublished": date_iso,
                "author": {"@type": "Person", "name": author},
                "mainEntityOfPage": canonical,
                "url": canonical,
            },
            ensure_ascii=False,
        )
        out_dir = OUT_P / slug
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "index.html").write_text(
            POST_TEMPLATE.format(
                title_esc=html.escape(title),
                excerpt_esc=html.escape(excerpt, quote=True),
                author_esc=html.escape(author),
                canonical=canonical,
                legacy_id_esc=html.escape(legacy_id),
                legacy_id_url=legacy_id_url,
                date_iso=html.escape(date_iso),
                tags_html=tags_html,
                body_html=body_html,
                jsonld=jsonld,
            ),
            encoding="utf-8",
        )
        sitemap_urls.append((canonical, date_iso))
        print(f"wrote p/{slug}/index.html  <- legacy #post/{legacy_id}")

    (ROOT / "post-map.json").write_text(json.dumps(mapping, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    sm = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for loc, lastmod in sitemap_urls:
        sm.append("  <url>")
        sm.append(f"    <loc>{html.escape(loc)}</loc>")
        sm.append(f"    <lastmod>{html.escape(lastmod)}</lastmod>")
        sm.append("  </url>")
    sm.append("</urlset>")
    (ROOT / "sitemap.xml").write_text("\n".join(sm) + "\n", encoding="utf-8")

    (ROOT / "robots.txt").write_text(
        "User-agent: *\nAllow: /\n" f"Sitemap: {SITE}/sitemap.xml\n",
        encoding="utf-8",
    )

    llms_lines = ["# Offensive32 Labs Blog", f"> Base: {SITE}/", "", "Static crawlable mirrors (legacy #post/ URLs still work for humans):", ""]
    for p in posts:
        slug = mapping[p["id"]]
        llms_lines.append(f"- [{html.unescape(p.get('title', slug))}]({SITE}/p/{slug}/): {p.get('excerpt', '')}")
    llms_lines += ["", f"- Sitemap: {SITE}/sitemap.xml", "- Contact: contact@offensive32.com", ""]
    (ROOT / "llms.txt").write_text("\n".join(llms_lines), encoding="utf-8")

    (ROOT / "404.html").write_text(
        """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>404 // NOT_FOUND | Offensive32 Labs Blog</title><meta name="robots" content="noindex"><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%230a0a0a'/%3E%3Ctext x='6' y='22' font-family='monospace' font-size='16' fill='%2300fff9'%3E%3E_%3C/text%3E%3C/svg%3E"><link rel="stylesheet" href="/style.css"></head><body><main class="terminal"><h1>[ 404 // NOT_FOUND ]</h1><p>// requested sector does not exist</p><p><a href="/">&larr; back to terminal</a></p></main></body></html>\n""",
        encoding="utf-8",
    )

    index_path = ROOT / "index.html"
    try:
        index_html = index_path.read_text(encoding="utf-8")
        items = []
        for p in posts:
            slug = mapping[p["id"]]
            title = p.get("title", slug)
            excerpt = p.get("excerpt") or ""
            items.append(
                f'<li><a href="/p/{slug}/">{html.escape(title)} - {html.escape(excerpt)}</a></li>'
            )
        noscript_block = (
            "<noscript>\n<h1>Offensive32 Labs Blog - Malware Analysis, Reverse Engineering, Threat Hunting</h1>\n"
            "<p>Offensive32 Security Research Blog - Malware Analysis, Reverse Engineering, Threat Hunting, "
            "Vulnerability Research. Enable JavaScript for terminal UI, or read the static mirrors:</p>\n<ul>\n"
            + "\n".join(items)
            + "\n</ul>\n</noscript>"
        )
        new_index, n = re.subn(r"<noscript>.*?</noscript>", noscript_block, index_html, flags=re.DOTALL)
        if n:
            index_path.write_text(new_index, encoding="utf-8")
            print(f"patched index.html noscript with {len(items)} links")
        else:
            print("WARN: no <noscript> block found in index.html, skipped patch")
    except Exception as e:
        print(f"WARN: noscript patch failed: {e}")

    print(f"done: {len(posts)} mirrors + sitemap.xml + robots.txt + llms.txt + 404.html + post-map.json")


if __name__ == "__main__":
    main()
