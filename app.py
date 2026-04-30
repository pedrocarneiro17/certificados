import io
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

# Carrega .env se existir (local). Em produção (Railway) usa as vars do sistema.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import NameOID
from flask import (Flask, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB

app.secret_key = os.environ.get("SECRET_KEY", "dev-key-troque-em-producao")

_db_url = os.environ.get("DATABASE_URL", "sqlite:///certs.db")
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

LOGIN_USER         = os.environ.get("LOGIN_USER", "admin")
LOGIN_PASS         = os.environ.get("LOGIN_PASSWORD", "admin123")
DEFAULT_CERT_PASS  = os.environ.get("DEFAULT_CERT_PASSWORD", "")


# ── Model ─────────────────────────────────────────────────────────────────────

class Certificate(db.Model):
    __tablename__ = "certificates"
    id           = db.Column(db.Integer, primary_key=True)
    filename     = db.Column(db.String(255), nullable=False)
    owner_name   = db.Column(db.String(500))
    organization = db.Column(db.String(500))
    not_before   = db.Column(db.DateTime(timezone=True))
    not_after    = db.Column(db.DateTime(timezone=True))
    file_data    = db.Column(db.LargeBinary, nullable=False)
    uploaded_at  = db.Column(db.DateTime(timezone=True),
                             default=lambda: datetime.now(timezone.utc))


with app.app_context():
    db.create_all()


# ── Auth ──────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Não autorizado"}), 401
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if data.get("username") == LOGIN_USER and data.get("password") == LOGIN_PASS:
        session["logged_in"] = True
        return jsonify({"success": True})
    return jsonify({"error": "Usuário ou senha inválidos"}), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})


# ── Certificate parsing ───────────────────────────────────────────────────────

def _cert_date(cert, which):
    """Compat: cryptography ≥42 expõe *_utc; versões antigas não."""
    try:
        return cert.not_valid_after_utc if which == "after" else cert.not_valid_before_utc
    except AttributeError:
        d = cert.not_valid_after if which == "after" else cert.not_valid_before
        return d.replace(tzinfo=timezone.utc)


def parse_pfx(data: bytes, password):
    try:
        pwd = password.encode() if isinstance(password, str) else password
        _, cert, extras = pkcs12.load_key_and_certificates(data, pwd)

        all_certs = ([cert] if cert else []) + list(extras or [])
        if not all_certs:
            return None, "Nenhum certificado encontrado no arquivo."

        def is_ca(c):
            try:
                bc = c.extensions.get_extension_for_class(x509.BasicConstraints)
                return bc.value.ca
            except x509.ExtensionNotFound:
                return False

        leaves = [c for c in all_certs if not is_ca(c)]
        pool = leaves or all_certs
        # Menor duração = certificado do titular, não da AC raiz
        selected = min(pool, key=lambda c: (
            _cert_date(c, "after") - _cert_date(c, "before")
        ).total_seconds())

        def attr(oid):
            try:
                return selected.subject.get_attributes_for_oid(oid)[0].value
            except Exception:
                return None

        return {
            "nome":       attr(NameOID.COMMON_NAME) or "Não identificado",
            "org":        attr(NameOID.ORGANIZATION_NAME),
            "not_before": _cert_date(selected, "before"),
            "not_after":  _cert_date(selected, "after"),
        }, None

    except Exception as e:
        return None, str(e)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _aware(dt):
    """SQLite devolve datetimes naive; normaliza para UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _row(c, now):
    not_after = _aware(c.not_after)
    dias = (not_after - now).days if not_after else None
    return {
        "id":           c.id,
        "filename":     c.filename,
        "owner_name":   c.owner_name,
        "organization": c.organization,
        "not_before":   _aware(c.not_before).isoformat() if c.not_before else None,
        "not_after":    not_after.isoformat()            if not_after   else None,
        "dias_restantes": dias,
        "uploaded_at":  c.uploaded_at.isoformat() if c.uploaded_at else None,
    }


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/dashboard")
@login_required
def api_dashboard():
    now = datetime.now(timezone.utc)

    def expiring(days):
        rows = (Certificate.query
                .filter(Certificate.not_after.between(now, now + timedelta(days=days)))
                .order_by(Certificate.not_after)
                .all())
        return [_row(c, now) for c in rows]

    return jsonify({
        "total":        Certificate.query.count(),
        "valid":        Certificate.query.filter(Certificate.not_after >= now).count(),
        "expired":      Certificate.query.filter(Certificate.not_after < now).count(),
        "expiring_45":  expiring(45),
        "expiring_30":  expiring(30),
        "expiring_15":  expiring(15),
    })


@app.route("/api/certificates")
@login_required
def api_list():
    now = datetime.now(timezone.utc)
    q = Certificate.query

    search = request.args.get("search", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(db.or_(
            Certificate.owner_name.ilike(like),
            Certificate.organization.ilike(like),
            Certificate.filename.ilike(like),
        ))

    quick     = request.args.get("quick", "")
    date_from = request.args.get("date_from", "")
    date_to   = request.args.get("date_to", "")

    if quick == "expired":
        q = q.filter(Certificate.not_after < now)
    elif quick in ("15", "30", "45"):
        q = q.filter(Certificate.not_after.between(now, now + timedelta(days=int(quick))))
    else:
        if date_from:
            try:
                q = q.filter(Certificate.not_after >=
                              datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc))
            except ValueError:
                pass
        if date_to:
            try:
                q = q.filter(Certificate.not_after <=
                              datetime.fromisoformat(date_to).replace(tzinfo=timezone.utc))
            except ValueError:
                pass

    rows = q.order_by(Certificate.not_after.asc()).all()
    return jsonify([_row(c, now) for c in rows])


@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    files    = request.files.getlist("files")
    manual_pw = request.form.get("password", "")
    results  = []

    for f in files:
        data     = f.read()
        filename = f.filename
        info     = None

        for pwd in filter(None, [DEFAULT_CERT_PASS, manual_pw, ""]):
            info, _ = parse_pfx(data, pwd)
            if info:
                break

        if info is None:
            results.append({"filename": filename, "success": False, "needs_password": True})
            continue

        now  = datetime.now(timezone.utc)
        cert = Certificate(
            filename     = filename,
            owner_name   = info["nome"],
            organization = info["org"],
            not_before   = info["not_before"],
            not_after    = info["not_after"],
            file_data    = data,
        )
        db.session.add(cert)
        db.session.commit()
        results.append({**_row(cert, now), "success": True})

    return jsonify(results)


@app.route("/api/certificates/<int:cid>/download")
@login_required
def api_download(cid):
    cert = db.get_or_404(Certificate, cid)
    return send_file(
        io.BytesIO(cert.file_data),
        download_name=cert.filename,
        as_attachment=True,
        mimetype="application/x-pkcs12",
    )


@app.route("/api/certificates/<int:cid>", methods=["DELETE"])
@login_required
def api_delete(cid):
    cert = db.get_or_404(Certificate, cid)
    db.session.delete(cert)
    db.session.commit()
    return jsonify({"success": True})


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if not session.get("logged_in"):
        return render_template("login.html")
    return render_template("index.html", login_user=LOGIN_USER)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
