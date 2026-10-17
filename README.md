# WebAble – Web Accessibility Analyzer
BSc Computer Science final year project. Flask + BeautifulSoup + SQLite.

## Features
- Register / login / logout / forgot password (time-limited reset link) (hashed passwords, CSRF protection, protected dashboard)
- Real analysis of any public URL: title, image ALT, H1, heading order, links, buttons, form labels, page language
- Score, summary cards, and per-issue explanation with fix and example code
- Blocks localhost/private addresses (SSRF protection)

## Run
```bash
python -m venv venv
venv\Scripts\activate        # Windows  (Linux/Mac: source venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env         # then set SECRET_KEY
python app.py
```
Open http://127.0.0.1:5000

## Structure
`app.py` routes/auth · `analyzer.py` checks · `templates/` · `static/style.css`
The SQLite file `webable.db` is created automatically and is git-ignored.
