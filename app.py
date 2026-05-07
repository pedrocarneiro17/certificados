import atexit
import io
import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

import requests as http
from apscheduler.schedulers.background import BackgroundScheduler

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

LOGIN_USER        = os.environ.get("LOGIN_USER", "admin")
LOGIN_PASS        = os.environ.get("LOGIN_PASSWORD", "admin123")
DEFAULT_CERT_PASS = os.environ.get("DEFAULT_CERT_PASSWORD", "")
EXTERNAL_API_URL  = os.environ.get("EXTERNAL_API_URL",
                                   "https://scceqfhksjflnlchlnqd.supabase.co/functions/v1/external-insert")
EXTERNAL_API_KEY  = os.environ.get("EXTERNAL_API_KEY", "")


# ── Models ────────────────────────────────────────────────────────────────────

class Certificate(db.Model):
    __tablename__ = "certificates"
    id           = db.Column(db.Integer, primary_key=True)
    filename     = db.Column(db.String(255), nullable=False)
    owner_name   = db.Column(db.String(500))
    organization = db.Column(db.String(500))
    cnpj         = db.Column(db.String(20))          # extraído do CN, se PJ
    not_before   = db.Column(db.DateTime(timezone=True))
    not_after    = db.Column(db.DateTime(timezone=True))
    file_data    = db.Column(db.LargeBinary, nullable=False)
    uploaded_at  = db.Column(db.DateTime(timezone=True),
                             default=lambda: datetime.now(timezone.utc))
    notifications = db.relationship("NotificationLog", backref="certificate",
                                    cascade="all, delete-orphan", passive_deletes=True)


class NotificationLog(db.Model):
    """Registra cada notificação enviada para evitar duplicatas."""
    __tablename__ = "notification_logs"
    id         = db.Column(db.Integer, primary_key=True)
    cert_id    = db.Column(db.Integer, db.ForeignKey("certificates.id", ondelete="CASCADE"))
    threshold  = db.Column(db.Integer)               # 30, 15 ou 7
    sent_at    = db.Column(db.DateTime(timezone=True),
                           default=lambda: datetime.now(timezone.utc))
    success    = db.Column(db.Boolean, default=True)
    response   = db.Column(db.Text)                  # resposta da API (debug)
    __table_args__ = (db.UniqueConstraint("cert_id", "threshold",
                                          name="uq_cert_threshold"),)


with app.app_context():
    db.create_all()
    # Migração: adiciona coluna cnpj em bases antigas (SQLite e PostgreSQL)
    for col, ddl in [("cnpj", "VARCHAR(20)")]:
        try:
            with db.engine.connect() as conn:
                conn.execute(db.text(f"ALTER TABLE certificates ADD COLUMN {col} {ddl}"))
                conn.commit()
        except Exception:
            pass  # coluna já existe


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
    try:
        return cert.not_valid_after_utc if which == "after" else cert.not_valid_before_utc
    except AttributeError:
        d = cert.not_valid_after if which == "after" else cert.not_valid_before
        return d.replace(tzinfo=timezone.utc)


def extract_cnpj(owner_name: str) -> str | None:
    """
    Certificados ICP-Brasil têm CN no formato 'NOME:DOCUMENTO'.
    PJ → 14 dígitos (CNPJ)  ex: 12.345.678/0001-95
    PF → 11 dígitos (CPF)   ex: 123.456.789-01
    """
    if not owner_name:
        return None
    clean = re.sub(r"[.\-/]", "", owner_name)
    match = re.search(r":(\d{11,14})", clean)
    if not match:
        return None
    d = match.group(1)
    if len(d) == 14:   # CNPJ
        return f"{d[:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:]}"
    if len(d) == 11:   # CPF
        return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"
    return None


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
        pool   = leaves or all_certs
        selected = min(pool, key=lambda c: (
            _cert_date(c, "after") - _cert_date(c, "before")
        ).total_seconds())

        def attr(oid):
            try:
                return selected.subject.get_attributes_for_oid(oid)[0].value
            except Exception:
                return None

        nome = attr(NameOID.COMMON_NAME) or "Não identificado"
        return {
            "nome":       nome,
            "org":        attr(NameOID.ORGANIZATION_NAME),
            "cnpj":       extract_cnpj(nome),
            "not_before": _cert_date(selected, "before"),
            "not_after":  _cert_date(selected, "after"),
        }, None

    except Exception as e:
        return None, str(e)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _aware(dt):
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _row(c, now):
    not_after = _aware(c.not_after)
    dias = (not_after - now).days if not_after else None
    return {
        "id":             c.id,
        "filename":       c.filename,
        "owner_name":     c.owner_name,
        "organization":   c.organization,
        "cnpj":           c.cnpj,
        "not_before":     _aware(c.not_before).isoformat() if c.not_before else None,
        "not_after":      not_after.isoformat()            if not_after   else None,
        "dias_restantes": dias,
        "uploaded_at":    c.uploaded_at.isoformat()        if c.uploaded_at else None,
    }


# ── Notifications ─────────────────────────────────────────────────────────────

# Buckets exclusivos (from_days exclusivo, to_days inclusivo) e label
THRESHOLDS = [
    (-1,  7,  7),   # 0–7 dias   → notificação "7"
    ( 7, 15, 15),   # 8–15 dias  → notificação "15"
    (15, 30, 30),   # 16–30 dias → notificação "30"
]


def _do_notify():
    """
    Verifica certificados em cada bucket exclusivo e envia para a API
    externa apenas os que ainda não foram notificados naquele bucket.
    """
    if not EXTERNAL_API_KEY:
        return [], "EXTERNAL_API_KEY não configurada."

    now     = datetime.now(timezone.utc)
    results = []

    for from_days, to_days, threshold in THRESHOLDS:
        expiring = (Certificate.query
                    .filter(
                        Certificate.not_after >  now + timedelta(days=from_days),
                        Certificate.not_after <= now + timedelta(days=to_days),
                    )
                    .all())

        for cert in expiring:
            # Já notificado para este limiar?
            already = NotificationLog.query.filter_by(
                cert_id=cert.id, threshold=threshold
            ).first()
            if already:
                continue

            cnpj = cert.cnpj or extract_cnpj(cert.owner_name)
            if not cnpj:
                results.append({
                    "cert":      cert.owner_name,
                    "threshold": threshold,
                    "success":   False,
                    "msg":       "CNPJ não encontrado no certificado",
                })
                continue

            not_after = _aware(cert.not_after)
            # CNPJ contém "/" no formato XX.XXX.XXX/XXXX-XX; CPF não
            is_cnpj = "/" in cnpj
            payload = {
                "action":            "insert_certificate_task",
                "cnpj" if is_cnpj else "cpf": cnpj,
                "client_name":       cert.owner_name,
                "days_until_expiry": threshold,
                "expiry_date":       not_after.strftime("%d/%m/%Y") if not_after else None,
            }

            try:
                resp = http.post(
                    EXTERNAL_API_URL,
                    json=payload,
                    headers={"x-api-key": EXTERNAL_API_KEY,
                             "Content-Type": "application/json"},
                    timeout=10,
                )
                success      = resp.status_code < 300
                response_txt = resp.text[:500]
            except Exception as e:
                success      = False
                response_txt = str(e)

            log = NotificationLog(
                cert_id   = cert.id,
                threshold = threshold,
                success   = success,
                response  = response_txt,
            )
            db.session.add(log)
            db.session.commit()

            results.append({
                "cert":      cert.owner_name,
                "cnpj":      cnpj,
                "threshold": threshold,
                "success":   success,
                "msg":       response_txt if not success else "OK",
            })

    return results, None


@app.route("/api/notify", methods=["POST"])
@login_required
def api_notify():
    results, err = _do_notify()
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"sent": len(results), "results": results})


@app.route("/api/notify/log")
@login_required
def api_notify_log():
    """Últimas 100 notificações enviadas."""
    logs = (NotificationLog.query
            .order_by(NotificationLog.sent_at.desc())
            .limit(100)
            .all())
    return jsonify([{
        "id":        l.id,
        "cert_id":   l.cert_id,
        "cert_name": l.certificate.owner_name if l.certificate else "—",
        "threshold": l.threshold,
        "sent_at":   _aware(l.sent_at).isoformat() if l.sent_at else None,
        "success":   l.success,
    } for l in logs])


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/dashboard")
@login_required
def api_dashboard():
    now = datetime.now(timezone.utc)

    def expiring_range(from_days, to_days):
        """Intervalo exclusivo: (from_days, to_days] em dias."""
        rows = (Certificate.query
                .filter(
                    Certificate.not_after >  now + timedelta(days=from_days),
                    Certificate.not_after <= now + timedelta(days=to_days),
                )
                .order_by(Certificate.not_after)
                .all())
        return [_row(c, now) for c in rows]

    # Buckets exclusivos: 0-7 | 8-15 | 16-30
    e7  = expiring_range(-1, 7)   # inclui hoje (dias=0)
    e15 = expiring_range(7,  15)
    e30 = expiring_range(15, 30)

    return jsonify({
        "total":       Certificate.query.count(),
        "valid":       Certificate.query.filter(Certificate.not_after >= now).count(),
        "expired":     Certificate.query.filter(Certificate.not_after < now).count(),
        "expiring_30_count": len(e7) + len(e15) + len(e30),  # card resumo
        "expiring_7":  e7,
        "expiring_15": e15,
        "expiring_30": e30,
    })


@app.route("/api/certificates")
@login_required
def api_list():
    now = datetime.now(timezone.utc)
    q   = Certificate.query

    search = request.args.get("search", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(db.or_(
            Certificate.owner_name.ilike(like),
            Certificate.organization.ilike(like),
            Certificate.filename.ilike(like),
            Certificate.cnpj.ilike(like),
        ))

    quick     = request.args.get("quick", "")
    date_from = request.args.get("date_from", "")
    date_to   = request.args.get("date_to",   "")

    if quick == "expired":
        q = q.filter(Certificate.not_after < now)
    elif quick in ("7", "15", "30"):
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
    files     = request.files.getlist("files")
    manual_pw = request.form.get("password", "")
    results   = []

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
            cnpj         = info["cnpj"],
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


# ── Scheduler ────────────────────────────────────────────────────────────────

def _scheduled_notify():
    """Job diário: roda _do_notify() dentro do contexto do app."""
    with app.app_context():
        results, err = _do_notify()
        if err:
            app.logger.warning(f"[scheduler] {err}")
        else:
            sent = sum(1 for r in results if r.get("success"))
            app.logger.info(f"[scheduler] {len(results)} verificado(s), {sent} enviado(s)")


_notify_hour = int(os.environ.get("NOTIFY_HOUR", "8"))

# Inicia o scheduler apenas uma vez:
#   - Em produção (gunicorn --workers 1): sempre
#   - Em dev (flask run com reloader): só no processo filho (WERKZEUG_RUN_MAIN=true)
if os.environ.get("WERKZEUG_RUN_MAIN", "true") == "true":
    _scheduler = BackgroundScheduler(timezone="America/Sao_Paulo")
    _scheduler.add_job(_scheduled_notify, "cron", hour=_notify_hour, minute=0)
    _scheduler.start()
    atexit.register(_scheduler.shutdown)


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if not session.get("logged_in"):
        return render_template("login.html")
    return render_template("index.html", login_user=LOGIN_USER)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
