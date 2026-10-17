"""WebAble - Web Accessibility Analyzer (Flask)."""
import os
import re
import secrets
import smtplib
import sqlite3
from email.message import EmailMessage
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

from analyzer import AnalysisError, analyze

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
# Set SECRET_KEY in your environment / .env. The fallback is random per run (sessions reset on restart).
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(app.root_path, "webable.db"))
RESET_MAX_AGE = 30 * 60  # reset links are valid for 30 minutes
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            flash("Please log in to access the dashboard.", "warning")
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("csrf")
        if not token or token != request.form.get("csrf_token"):
            abort(400, "Invalid or missing CSRF token.")


@app.context_processor
def inject():
    session.setdefault("csrf", secrets.token_hex(16))
    return dict(csrf_token=session["csrf"], user_name=session.get("user_name"),
                user_email=session.get("user_email"))


@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm_password", "")
        error = None
        if not name:
            error = "Full name is required."
        elif not EMAIL_RE.match(email):
            error = "Please enter a valid email address."
        elif len(pw) < 8:
            error = "Password must be at least 8 characters long."
        elif pw != pw2:
            error = "Password and Confirm Password do not match."
        elif get_db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            error = "An account with this email already exists."
        if error:
            flash(error, "error")
            return render_template("register.html", full_name=name, email=email), 400
        get_db().execute("INSERT INTO users (full_name, email, password_hash) VALUES (?,?,?)",
                         (name, email, generate_password_hash(pw)))
        get_db().commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        if not EMAIL_RE.match(email):
            flash("Please enter a valid email address.", "error")
            return render_template("login.html", email=email), 400
        user = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], pw):
            flash("Incorrect email or password.", "error")
            return render_template("login.html", email=email), 401
        session.clear()
        session.update(user_id=user["id"], user_name=user["full_name"], user_email=user["email"],
                       csrf=secrets.token_hex(16))
        flash(f"Welcome back, {user['full_name']}!", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


# ---------------- Forgot / reset password ----------------
def _serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="webable-password-reset")


def make_reset_token(user):
    # The password hash is part of the token, so a link stops working once the password is changed.
    return _serializer().dumps({"id": user["id"], "h": user["password_hash"][-12:]})


def load_reset_user(token):
    try:
        data = _serializer().loads(token, max_age=RESET_MAX_AGE)
    except (SignatureExpired, BadSignature):
        return None
    user = get_db().execute("SELECT * FROM users WHERE id=?", (data.get("id"),)).fetchone()
    if user and user["password_hash"][-12:] == data.get("h"):
        return user
    return None


def send_reset_link(email, link):
    """Send the link by e-mail if SMTP is configured, otherwise print it in the server console (local demo)."""
    host = os.environ.get("SMTP_HOST")
    if not host:
        print(f"\n[WebAble] Password reset link for {email} (valid 30 minutes):\n{link}\n")
        return
    msg = EmailMessage()
    msg["Subject"] = "WebAble – reset your password"
    msg["From"] = os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USER", "")
    msg["To"] = email
    msg.set_content(f"Click the link to reset your WebAble password (valid for 30 minutes):\n\n{link}\n\n"
                    "If you did not ask for this, you can ignore this e-mail.")
    try:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=15) as s:
            s.starttls()
            s.login(os.environ.get("SMTP_USER", ""), os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)
    except Exception as exc:  # never reveal mail problems to the visitor
        print(f"[WebAble] Could not send reset e-mail: {exc}\nLink: {link}")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not EMAIL_RE.match(email):
            flash("Please enter a valid email address.", "error")
            return render_template("forgot_password.html", email=email), 400
        user = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user:
            send_reset_link(email, url_for("reset_password", token=make_reset_token(user), _external=True))
        # Same message whether or not the account exists (does not reveal registered emails)
        flash("If an account exists for this email, a password reset link has been sent.", "success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = load_reset_user(token)
    if not user:
        flash("This reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm_password", "")
        error = None
        if len(pw) < 8:
            error = "Password must be at least 8 characters long."
        elif pw != pw2:
            error = "Password and Confirm Password do not match."
        if error:
            flash(error, "error")
            return render_template("reset_password.html", token=token), 400
        get_db().execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(pw), user["id"]))
        get_db().commit()
        flash("Password changed successfully. Please log in with your new password.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/analyze", methods=["POST"])
@login_required
def analyze_view():
    url = request.form.get("url", "")
    try:
        result = analyze(url)
    except AnalysisError as e:
        flash(str(e), "error")
        return render_template("dashboard.html", url=url), 400
    return render_template("results.html", r=result)


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")


init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
