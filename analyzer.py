"""WebAble analyzer: fetches a public web page and runs real accessibility checks."""
import ipaddress
import re
import socket
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "WebAble-Accessibility-Analyzer/1.0 (college project)"}
VAGUE = {"click here", "here", "read more", "more", "link", "learn more", "this"}


class AnalysisError(Exception):
    """Raised with a user-friendly message."""


def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise AnalysisError("Please enter a website URL.")
    if " " in raw:
        raise AnalysisError("A URL cannot contain spaces.")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        raise AnalysisError("Only http:// and https:// URLs are supported.")
    host = p.hostname
    if not host or "." not in host:
        raise AnalysisError("Invalid URL. Try something like https://example.com")
    return raw


def _check_public(host):
    """Block localhost/private addresses (SSRF protection)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise AnalysisError("Could not find that website. Check the address and try again.")
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise AnalysisError("Only public websites can be analyzed.")


def fetch(url):
    for _ in range(5):  # follow redirects manually, re-checking each hop
        _check_public(urlparse(url).hostname)
        try:
            r = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=False)
        except requests.exceptions.SSLError:
            raise AnalysisError("The website has an invalid SSL certificate.")
        except requests.exceptions.Timeout:
            raise AnalysisError("The website took too long to respond.")
        except requests.exceptions.RequestException:
            raise AnalysisError("Could not connect to the website.")
        if r.is_redirect and r.headers.get("Location"):
            url = urljoin(url, r.headers["Location"])
            continue
        if r.status_code >= 400:
            raise AnalysisError(f"The website returned an error (HTTP {r.status_code}).")
        if "html" not in r.headers.get("Content-Type", "").lower():
            raise AnalysisError("That URL does not point to an HTML page.")
        return url, r.text
    raise AnalysisError("Too many redirects.")


def _r(name, status, found, issue=None, wrong=None, why=None, fix=None, code=None):
    return dict(name=name, status=status, found=found, issue=issue,
                wrong=wrong, why=why, fix=fix, code=code)


def _name(tag):
    """Accessible name approximation for links/buttons."""
    txt = tag.get_text(" ", strip=True)
    if txt:
        return txt
    for a in ("aria-label", "title", "value"):
        if tag.get(a, "").strip():
            return tag[a].strip()
    img = tag.find("img", alt=True)
    return img["alt"].strip() if img else ""


def run_checks(soup):
    out = []

    # 1. Page title
    t = soup.title.get_text(strip=True) if soup.title else ""
    if not t:
        out.append(_r("Page Title", "failed", "No <title> found", "Missing page title",
                      "The page has no <title>, or it is empty.",
                      "The title is the first thing screen readers announce and is used in tabs and bookmarks.",
                      "Add a short, descriptive title inside <head>.",
                      "<head>\n  <title>Contact Us - Company Name</title>\n</head>"))
    elif len(t) > 70 or t.lower() in ("untitled", "home", "document"):
        out.append(_r("Page Title", "warning", f'Title: "{t[:80]}"', "Page title is vague or too long",
                      "The title is generic or longer than ~70 characters.",
                      "Unclear titles make it hard to tell pages apart.",
                      "Use a concise title that describes this page's purpose.",
                      "<title>Pricing Plans - Company Name</title>"))
    else:
        out.append(_r("Page Title", "passed", f'Title: "{t}"'))

    # 2. Images ALT
    imgs = soup.find_all("img")
    missing = [i for i in imgs if i.get("alt") is None]
    fname = [i for i in imgs if i.get("alt") and re.search(r"\.(png|jpe?g|gif|svg|webp)$", i["alt"].strip(), re.I)]
    if missing:
        ex = str(missing[0].attrs.get("src", "logo.png"))[:60]
        out.append(_r("Images ALT Text", "failed", f"{len(missing)} of {len(imgs)} images have no alt attribute",
                      "Images missing ALT text", "Some images do not have alternative text.",
                      "Screen readers may not be able to understand the purpose of the image.",
                      'Add meaningful ALT text. Use alt="" only for purely decorative images.',
                      f'<img src="{ex}" alt="Company Logo">'))
    elif fname:
        out.append(_r("Images ALT Text", "warning", f"{len(fname)} images use a file name as ALT text",
                      "ALT text looks like a file name", "ALT text such as 'photo.jpg' does not describe the image.",
                      "Screen reader users hear the file name instead of useful information.",
                      "Describe what the image shows or its function.",
                      '<img src="team.jpg" alt="Our team at the 2025 annual meeting">'))
    else:
        out.append(_r("Images ALT Text", "passed", f"All {len(imgs)} images have ALT text" if imgs else "No images found"))

    # 3. H1
    h1 = soup.find_all("h1")
    if not h1:
        out.append(_r("H1 Heading", "failed", "No <h1> found", "Missing H1 heading",
                      "The page has no main heading.",
                      "Screen reader users rely on the H1 to understand the page topic quickly.",
                      "Add exactly one <h1> describing the page.", "<h1>Welcome to Our Store</h1>"))
    elif len(h1) > 1:
        out.append(_r("H1 Heading", "warning", f"{len(h1)} <h1> elements found", "Multiple H1 headings",
                      "The page has more than one main heading.",
                      "Multiple H1s can confuse the page outline.",
                      "Keep one <h1>; use <h2>-<h6> for sections.",
                      "<h1>Main Title</h1>\n<h2>Section Title</h2>"))
    else:
        out.append(_r("H1 Heading", "passed", f'H1: "{h1[0].get_text(strip=True)[:60]}"'))

    # 4. Heading structure
    levels = [int(h.name[1]) for h in soup.find_all(re.compile(r"^h[1-6]$"))]
    skips = [(a, b) for a, b in zip(levels, levels[1:]) if b - a > 1]
    if not levels:
        out.append(_r("Heading Structure", "failed", "No headings found", "No headings used",
                      "The page has no heading elements.",
                      "Headings let screen reader users jump between sections.",
                      "Organise content with headings in order.", "<h1>Title</h1>\n<h2>Section</h2>\n<h3>Subsection</h3>"))
    elif skips:
        out.append(_r("Heading Structure", "warning", f"{len(skips)} skipped level(s), e.g. H{skips[0][0]} to H{skips[0][1]}",
                      "Heading levels are skipped", "Heading levels jump (for example H2 straight to H4).",
                      "Skipped levels break the logical outline for assistive technology.",
                      "Use headings in order without skipping levels.",
                      "<h2>Services</h2>\n<h3>Web Design</h3>  <!-- not <h4> -->"))
    else:
        out.append(_r("Heading Structure", "passed", f"{len(levels)} headings in a logical order"))

    # 5. Links
    links = soup.find_all("a", href=True)
    empty = [a for a in links if not _name(a)]
    vague = [a for a in links if _name(a).lower().strip(" .>") in VAGUE]
    if empty:
        out.append(_r("Links", "failed", f"{len(empty)} of {len(links)} links have no accessible text",
                      "Links without text", "Some links have no text, label or image ALT.",
                      "Screen readers announce just 'link', so users cannot tell where it goes.",
                      "Add visible text or an aria-label.",
                      '<a href="/cart" aria-label="View shopping cart">\n  <i class="icon-cart"></i>\n</a>'))
    elif vague:
        out.append(_r("Links", "warning", f"{len(vague)} links use vague text like 'click here'",
                      "Vague link text", "Link text such as 'click here' or 'read more' lacks context.",
                      "Users listing links out of context cannot tell them apart.",
                      "Make the link text describe the destination.",
                      '<a href="/report.pdf">Download the 2025 annual report</a>'))
    else:
        out.append(_r("Links", "passed", f"All {len(links)} links have descriptive text" if links else "No links found"))

    # 6. Buttons
    btns = soup.find_all("button") + soup.find_all("input", type=re.compile(r"^(submit|button|reset)$", re.I))
    nameless = [b for b in btns if not _name(b)]
    if nameless:
        out.append(_r("Buttons", "failed", f"{len(nameless)} of {len(btns)} buttons have no accessible name",
                      "Buttons without a name", "Some buttons have no text or label.",
                      "Screen reader users will not know what the button does.",
                      "Add text or an aria-label to the button.",
                      '<button type="button" aria-label="Close dialog">X</button>'))
    else:
        out.append(_r("Buttons", "passed", f"All {len(btns)} buttons are labelled" if btns else "No buttons found"))

    # 7. Form labels
    fields = soup.find_all(["input", "select", "textarea"])
    fields = [f for f in fields if f.name != "input" or f.get("type", "text").lower() not in
              ("hidden", "submit", "button", "reset", "image")]
    ids = {l.get("for") for l in soup.find_all("label") if l.get("for")}
    bad = [f for f in fields if not (f.get("id") in ids or f.find_parent("label") or
                                      f.get("aria-label") or f.get("aria-labelledby") or f.get("title"))]
    if bad:
        out.append(_r("Form Labels", "failed", f"{len(bad)} of {len(fields)} form fields have no label",
                      "Form fields missing labels", "Some inputs are not linked to a <label>.",
                      "Screen readers cannot announce what to type, and clicking the label will not focus the field.",
                      "Link each input to a label using for and id.",
                      '<label for="email">Email address</label>\n<input type="email" id="email" name="email">'))
    else:
        out.append(_r("Form Labels", "passed", f"All {len(fields)} form fields are labelled" if fields else "No form fields found"))

    # 8. Language
    lang = (soup.html.get("lang", "") if soup.html else "").strip()
    if not lang:
        out.append(_r("Page Language", "warning", "No lang attribute on <html>", "Missing page language",
                      "The <html> tag does not declare a language.",
                      "Screen readers need it to choose the correct pronunciation.",
                      "Add a lang attribute to <html>.", '<html lang="en">'))
    else:
        out.append(_r("Page Language", "passed", f'lang="{lang}"'))
    return out


def image_report(soup, base):
    """Per-image diagnostics for the Image Diagnostic panel."""
    items = []
    for i in soup.find_all("img")[:60]:
        src = urljoin(base, i.get("src") or i.get("data-src") or "")
        alt = i.get("alt")
        if alt is None:
            st, note = "failed", "Missing alt attribute"
        elif alt.strip() == "":
            st, note = "passed", 'Decorative image (alt="")'
        elif re.fullmatch(r"(image|img|photo|picture|graphic|icon)[\s_-]*\d*", alt.strip(), re.I) or \
                re.search(r"\.(png|jpe?g|gif|svg|webp)$", alt.strip(), re.I):
            st, note = "warning", f'Vague ALT text ("{alt.strip()[:40]}")'
        else:
            st, note = "passed", f'ALT: "{alt.strip()[:60]}"'
        items.append(dict(src=src, status=st, note=note))
    return items


def analyze(raw_url):
    url, html = fetch(normalize_url(raw_url))
    soup = BeautifulSoup(html, "html.parser")
    checks = run_checks(soup)
    images = image_report(soup, url)
    n = {s: sum(c["status"] == s for c in checks) for s in ("passed", "warning", "failed")}
    score = round((n["passed"] + 0.5 * n["warning"]) / len(checks) * 100)
    return dict(url=url, checked_at=datetime.now().strftime("%d %b %Y, %H:%M"), score=score,
                total=len(checks), passed=n["passed"], warnings=n["warning"], failed=n["failed"], checks=checks, images=images)
