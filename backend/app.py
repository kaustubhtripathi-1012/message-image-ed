#!/usr/bin/env python3
"""
SecureVault — Secure Message & Image Encryption System
Flask Backend API  •  v1.0
"""

import os
import uuid
import secrets
import hashlib
import datetime
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from sqlalchemy import (
    create_engine, Column, String, Integer, DateTime, Text, event as sa_event,
    text as sa_text, or_
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker, scoped_session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# ─────────────────────────────────────────────────────────────────────────────
#  Paths & Config
# ─────────────────────────────────────────────────────────────────────────────
# Resolve all paths relative to this file's real location
_THIS_FILE    = os.path.realpath(os.path.abspath(__file__))
BASE_DIR      = os.path.dirname(_THIS_FILE)
FRONTEND_DIR  = os.path.normpath(os.path.join(BASE_DIR, '..', 'frontend'))

# Store DB and blobs in local AppData to avoid OneDrive / network drive issues
# (SQLite cannot open files on network-mapped or OneDrive-placeholder paths)
_LOCAL_DATA   = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'SecureVault')
BLOB_DIR      = os.path.join(_LOCAL_DATA, 'encrypted_blobs')
DB_PATH       = os.path.join(_LOCAL_DATA, 'secure_vault.db')

# Ensure required directories exist
for _d in [_LOCAL_DATA, BLOB_DIR]:
    os.makedirs(_d, exist_ok=True)

SECRET_KEY            = os.environ.get('SECRET_KEY', secrets.token_hex(32))
SESSION_LIFETIME_HRS  = 24
ALLOWED_IMAGE_TYPES   = {'image/jpeg', 'image/png', 'image/webp', 'image/jpg'}
MAX_ENCRYPTED_SIZE    = 30 * 1024 * 1024   # 30 MB

# ─────────────────────────────────────────────────────────────────────────────
#  ORM Models
# ─────────────────────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'
    id            = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username      = Column(String(64),  unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    status        = Column(String(16),  default='active')
    created_at    = Column(DateTime,    default=datetime.datetime.utcnow)


class Session(Base):
    __tablename__ = 'sessions'
    id         = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = Column(String(36), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False)
    expires_at = Column(DateTime,   nullable=False)
    revoked    = Column(Integer,    default=0)
    created_at = Column(DateTime,   default=datetime.datetime.utcnow)


class Message(Base):
    __tablename__     = 'messages'
    id               = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id        = Column(String(36), nullable=False)
    recipient_id     = Column(String(36), nullable=False)
    ciphertext       = Column(Text,       nullable=False)   # base64 AES-GCM output
    nonce            = Column(String(64), nullable=False)   # base64 96-bit nonce
    salt             = Column(String(64), nullable=False)   # base64 128-bit PBKDF2 salt
    protocol_version = Column(Integer,    default=1)
    status           = Column(String(16), default='active')
    created_at       = Column(DateTime,   default=datetime.datetime.utcnow)


class EncryptedImage(Base):
    __tablename__     = 'encrypted_images'
    id               = Column(String(36),  primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id         = Column(String(36),  nullable=False)
    sender_id        = Column(String(36),  nullable=True)
    recipient_id     = Column(String(36),  nullable=True)
    original_name    = Column(String(256), nullable=False)
    blob_filename    = Column(String(256), nullable=False)
    nonce            = Column(String(64),  nullable=False)
    salt             = Column(String(64),  nullable=False)
    content_type     = Column(String(64),  nullable=False)
    encrypted_size   = Column(Integer,     nullable=False)
    protocol_version = Column(Integer,     default=1)
    status           = Column(String(16),  default='active')
    created_at       = Column(DateTime,    default=datetime.datetime.utcnow)


class TransferRequest(Base):
    __tablename__     = 'transfer_requests'
    id               = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id        = Column(String(36), nullable=False)
    recipient_id     = Column(String(36), nullable=False)
    status           = Column(String(16), default='pending')  # pending | accepted | declined
    created_at       = Column(DateTime,   default=datetime.datetime.utcnow)
    updated_at       = Column(DateTime,   default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class SecurityEvent(Base):
    __tablename__ = 'security_events'
    id         = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String(64), nullable=False)
    user_id    = Column(String(36), nullable=True)
    result     = Column(String(16), nullable=False)   # SUCCESS | FAILURE | WARNING
    severity   = Column(String(16), default='INFO')   # INFO | WARNING | ERROR
    request_id = Column(String(36), nullable=True)
    created_at = Column(DateTime,   default=datetime.datetime.utcnow)


# ─────────────────────────────────────────────────────────────────────────────
#  Database
# ─────────────────────────────────────────────────────────────────────────────
engine     = create_engine(
    f'sqlite:///{DB_PATH}',
    connect_args={'check_same_thread': False}
)
# Enable WAL mode for better concurrent read performance with SQLite
@sa_event.listens_for(engine, 'connect')
def set_sqlite_pragma(dbapi_conn, _):
    dbapi_conn.execute('PRAGMA journal_mode=WAL')
    dbapi_conn.execute('PRAGMA foreign_keys=ON')

Base.metadata.create_all(engine)

# Auto-migration for encrypted_images sender_id/recipient_id columns
with engine.connect() as conn:
    cols = [row[1] for row in conn.execute(sa_text("PRAGMA table_info(encrypted_images)")).fetchall()]
    if 'sender_id' not in cols:
        conn.execute(sa_text("ALTER TABLE encrypted_images ADD COLUMN sender_id VARCHAR(36)"))
    if 'recipient_id' not in cols:
        conn.execute(sa_text("ALTER TABLE encrypted_images ADD COLUMN recipient_id VARCHAR(36)"))
    conn.execute(sa_text("UPDATE encrypted_images SET sender_id = owner_id WHERE sender_id IS NULL"))
    conn.execute(sa_text("UPDATE encrypted_images SET recipient_id = owner_id WHERE recipient_id IS NULL"))
    conn.commit()

db_session = scoped_session(sessionmaker(bind=engine))

ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

# ─────────────────────────────────────────────────────────────────────────────
#  Flask App
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')
app.config['SECRET_KEY']         = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 35 * 1024 * 1024   # 35 MB hard limit
CORS(app, resources={r'/api/*': {'origins': '*'}})


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _log_event(event_type: str, user_id=None,
                result='SUCCESS', severity='INFO') -> None:
    """Record a security event — keep capacity capped at 20."""
    try:
        evt = SecurityEvent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            user_id=user_id,
            result=result,
            severity=severity,
            request_id=str(uuid.uuid4()),
        )
        db_session.add(evt)
        db_session.commit()

        # Prune events for this user to maintain max capacity of 20
        if user_id:
            old_evts = (
                db_session.query(SecurityEvent.id)
                .filter_by(user_id=user_id)
                .order_by(SecurityEvent.created_at.desc())
                .offset(20)
                .all()
            )
            if old_evts:
                old_ids = [e[0] for e in old_evts]
                db_session.query(SecurityEvent).filter(SecurityEvent.id.in_(old_ids)).delete(synchronize_session=False)
                db_session.commit()
    except Exception:
        db_session.rollback()


def require_auth(f):
    """Decorator: validates Bearer token and attaches current user to request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        token      = auth[7:]
        token_hash = _hash_token(token)
        sess = db_session.query(Session).filter_by(
            token_hash=token_hash, revoked=0
        ).first()
        if not sess:
            return jsonify({'error': 'Unauthorized'}), 401
        if sess.expires_at < datetime.datetime.utcnow():
            return jsonify({'error': 'Session expired'}), 401
        user = db_session.query(User).filter_by(
            id=sess.user_id, status='active'
        ).first()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
#  Auth Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip().lower()
    password = str(data.get('password', ''))

    if not username or not (3 <= len(username) <= 32):
        return jsonify({'error': 'Username must be 3–32 characters'}), 400
    if not username.replace('_', '').replace('-', '').isalnum():
        return jsonify({'error': 'Username: only letters, numbers, _ and -'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be ≥ 8 characters'}), 400

    if db_session.query(User).filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 409

    user = User(username=username, password_hash=ph.hash(password))
    db_session.add(user)
    db_session.commit()
    _log_event('USER_REGISTERED', user_id=user.id)
    return jsonify({'message': 'Account created', 'username': username}), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip().lower()
    password = str(data.get('password', ''))

    user = db_session.query(User).filter_by(username=username, status='active').first()
    if not user:
        _log_event('LOGIN_FAILED', result='FAILURE', severity='WARNING')
        return jsonify({'error': 'Invalid credentials'}), 401

    try:
        ph.verify(user.password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        _log_event('LOGIN_FAILED', user_id=user.id, result='FAILURE', severity='WARNING')
        return jsonify({'error': 'Invalid credentials'}), 401

    token      = secrets.token_hex(32)
    token_hash = _hash_token(token)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=SESSION_LIFETIME_HRS)

    db_session.add(Session(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at
    ))
    db_session.commit()
    _log_event('LOGIN_SUCCESS', user_id=user.id)
    return jsonify({'token': token, 'username': user.username, 'user_id': user.id}), 200


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token      = request.headers.get('Authorization', '')[7:]
    token_hash = _hash_token(token)
    sess = db_session.query(Session).filter_by(token_hash=token_hash).first()
    if sess:
        sess.revoked = 1
        db_session.commit()
    _log_event('LOGOUT', user_id=request.current_user.id)
    return jsonify({'message': 'Logged out'}), 200


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    u = request.current_user
    return jsonify({'user_id': u.id, 'username': u.username}), 200


# ─────────────────────────────────────────────────────────────────────────────
#  User Directory  (public-ish — only username exposed)
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
@require_auth
def list_users():
    accepted_only = request.args.get('accepted_only', '0') == '1'
    uid = request.current_user.id
    if accepted_only:
        transfers = db_session.query(TransferRequest).filter(
            or_(TransferRequest.sender_id == uid, TransferRequest.recipient_id == uid),
            TransferRequest.status == 'accepted'
        ).all()
        accepted_ids = {t.sender_id if t.recipient_id == uid else t.recipient_id for t in transfers}
        if not accepted_ids:
            return jsonify([]), 200
        users = db_session.query(User).filter(User.id.in_(accepted_ids), User.status == 'active').all()
    else:
        users = (
            db_session.query(User)
            .filter(User.status == 'active', User.id != uid)
            .all()
        )
    return jsonify([{'user_id': u.id, 'username': u.username} for u in users]), 200


# ─────────────────────────────────────────────────────────────────────────────
#  Message Routes  (server stores ONLY ciphertext + metadata)
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/messages', methods=['POST'])
@require_auth
def send_message():
    data      = request.get_json(silent=True) or {}
    recipient = str(data.get('recipient', '')).strip().lower()
    ciphertext = str(data.get('ciphertext', ''))
    nonce      = str(data.get('nonce', ''))
    salt       = str(data.get('salt', ''))
    version    = int(data.get('version', 1))

    if not all([recipient, ciphertext, nonce, salt]):
        return jsonify({'error': 'Missing required fields'}), 400
    if len(ciphertext) > 120_000:   # ~90 KB base64 → 64 KB plaintext
        return jsonify({'error': 'Ciphertext too large'}), 413

    target = db_session.query(User).filter_by(username=recipient, status='active').first()
    if not target:
        return jsonify({'error': 'Recipient not found'}), 404

    # Verify that transfer request is accepted between sender and recipient
    transfer = db_session.query(TransferRequest).filter(
        or_(
            (TransferRequest.sender_id == request.current_user.id) & (TransferRequest.recipient_id == target.id),
            (TransferRequest.sender_id == target.id) & (TransferRequest.recipient_id == request.current_user.id)
        ),
        TransferRequest.status == 'accepted'
    ).first()
    if not transfer:
        return jsonify({'error': f'Transfer request has not been accepted by {recipient} yet'}), 403

    msg = Message(
        sender_id=request.current_user.id,
        recipient_id=target.id,
        ciphertext=ciphertext,
        nonce=nonce,
        salt=salt,
        protocol_version=version,
    )
    db_session.add(msg)
    db_session.commit()
    _log_event('MESSAGE_SENT', user_id=request.current_user.id)
    return jsonify({'message_id': msg.id, 'status': 'delivered'}), 201


@app.route('/api/messages/inbox', methods=['GET'])
@require_auth
def inbox():
    msgs = (
        db_session.query(Message)
        .filter_by(recipient_id=request.current_user.id, status='active')
        .order_by(Message.created_at.desc())
        .limit(50).all()
    )
    result = []
    for m in msgs:
        sender = db_session.query(User).filter_by(id=m.sender_id).first()
        result.append({
            'id': m.id, 'sender': sender.username if sender else 'unknown',
            'nonce': m.nonce, 'salt': m.salt, 'ciphertext': m.ciphertext,
            'version': m.protocol_version,
            'created_at': m.created_at.isoformat()
        })
    return jsonify(result), 200


@app.route('/api/messages/sent', methods=['GET'])
@require_auth
def sent_messages():
    msgs = (
        db_session.query(Message)
        .filter_by(sender_id=request.current_user.id, status='active')
        .order_by(Message.created_at.desc())
        .limit(50).all()
    )
    result = []
    for m in msgs:
        recipient = db_session.query(User).filter_by(id=m.recipient_id).first()
        result.append({
            'id': m.id, 'recipient': recipient.username if recipient else 'unknown',
            'nonce': m.nonce, 'salt': m.salt, 'ciphertext': m.ciphertext,
            'version': m.protocol_version,
            'created_at': m.created_at.isoformat()
        })
    return jsonify(result), 200


@app.route('/api/messages/<message_id>', methods=['DELETE'])
@require_auth
def delete_message(message_id):
    msg = db_session.query(Message).filter_by(id=message_id).first()
    if not msg:
        return jsonify({'error': 'Not found'}), 404
    uid = request.current_user.id
    if msg.sender_id != uid and msg.recipient_id != uid:
        _log_event('UNAUTHORIZED_DELETE', user_id=uid, result='FAILURE', severity='WARNING')
        return jsonify({'error': 'Forbidden'}), 403
    msg.status = 'deleted'
    db_session.commit()
    _log_event('MESSAGE_DELETED', user_id=uid)
    return jsonify({'message': 'Deleted'}), 200


# ─────────────────────────────────────────────────────────────────────────────
#  Image Routes  (server stores ONLY encrypted binary blob + metadata)
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/images', methods=['POST'])
@require_auth
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file         = request.files['file']
    nonce        = request.form.get('nonce', '')
    salt         = request.form.get('salt', '')
    content_type = request.form.get('content_type', '')
    orig_name    = request.form.get('original_name', 'image')[:256]
    version      = int(request.form.get('version', 1))
    recipient    = request.form.get('recipient', '').strip().lower()

    if not all([nonce, salt, content_type]):
        return jsonify({'error': 'Missing encryption metadata'}), 400
    if content_type not in ALLOWED_IMAGE_TYPES:
        return jsonify({'error': 'Unsupported image type'}), 415

    data = file.read()
    if len(data) > MAX_ENCRYPTED_SIZE:
        return jsonify({'error': 'File too large (max 30 MB encrypted)'}), 413

    # Check recipient if specified
    recipient_id = request.current_user.id
    if recipient:
        target = db_session.query(User).filter_by(username=recipient, status='active').first()
        if not target:
            return jsonify({'error': 'Recipient not found'}), 404
        # Verify transfer request is accepted
        transfer = db_session.query(TransferRequest).filter(
            or_(
                (TransferRequest.sender_id == request.current_user.id) & (TransferRequest.recipient_id == target.id),
                (TransferRequest.sender_id == target.id) & (TransferRequest.recipient_id == request.current_user.id)
            ),
            TransferRequest.status == 'accepted'
        ).first()
        if not transfer:
            return jsonify({'error': f'Transfer request has not been accepted by {recipient} yet'}), 403
        recipient_id = target.id

    blob_id   = str(uuid.uuid4())
    blob_file = f'{blob_id}.enc'
    blob_path = os.path.join(BLOB_DIR, blob_file)
    with open(blob_path, 'wb') as fh:
        fh.write(data)

    img = EncryptedImage(
        id=blob_id,
        owner_id=request.current_user.id,
        sender_id=request.current_user.id,
        recipient_id=recipient_id,
        original_name=orig_name, blob_filename=blob_file,
        nonce=nonce, salt=salt, content_type=content_type,
        encrypted_size=len(data), protocol_version=version,
    )
    db_session.add(img)
    db_session.commit()
    _log_event('IMAGE_UPLOADED', user_id=request.current_user.id)
    return jsonify({'image_id': blob_id}), 201


@app.route('/api/images', methods=['GET'])
@require_auth
def list_images():
    box = request.args.get('box', 'received').lower()
    uid = request.current_user.id

    if box == 'sent':
        query = db_session.query(EncryptedImage).filter(
            or_(EncryptedImage.sender_id == uid, (EncryptedImage.sender_id == None) & (EncryptedImage.owner_id == uid)),
            EncryptedImage.status == 'active'
        )
    else:
        query = db_session.query(EncryptedImage).filter(
            or_(
                EncryptedImage.recipient_id == uid,
                (EncryptedImage.recipient_id == None) & (EncryptedImage.owner_id == uid)
            ),
            EncryptedImage.status == 'active'
        )

    imgs = query.order_by(EncryptedImage.created_at.desc()).limit(50).all()

    # Preload user map for rich display of sender and recipient names
    user_ids = set()
    for i in imgs:
        if i.sender_id: user_ids.add(i.sender_id)
        elif i.owner_id: user_ids.add(i.owner_id)
        if i.recipient_id: user_ids.add(i.recipient_id)
    users_map = {u.id: u.username for u in db_session.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}

    return jsonify([{
        'id': i.id, 'original_name': i.original_name,
        'content_type': i.content_type, 'encrypted_size': i.encrypted_size,
        'nonce': i.nonce, 'salt': i.salt,
        'version': i.protocol_version, 'created_at': i.created_at.isoformat(),
        'sender': users_map.get(i.sender_id or i.owner_id, 'unknown'),
        'recipient': users_map.get(i.recipient_id or i.owner_id, 'self')
    } for i in imgs]), 200


@app.route('/api/images/<image_id>/data', methods=['GET'])
@require_auth
def download_image(image_id):
    uid = request.current_user.id
    img = db_session.query(EncryptedImage).filter_by(
        id=image_id, status='active'
    ).first()
    if not img:
        return jsonify({'error': 'Not found'}), 404
    if img.sender_id != uid and img.recipient_id != uid and img.owner_id != uid:
        _log_event('UNAUTHORIZED_IMAGE_ACCESS', user_id=uid, result='FAILURE', severity='WARNING')
        return jsonify({'error': 'Forbidden'}), 403

    blob_path = os.path.join(BLOB_DIR, img.blob_filename)
    if not os.path.isfile(blob_path):
        return jsonify({'error': 'Encrypted data unavailable'}), 404
    _log_event('IMAGE_DOWNLOADED', user_id=uid)
    return send_file(blob_path, mimetype='application/octet-stream')


@app.route('/api/images/<image_id>', methods=['DELETE'])
@require_auth
def delete_image(image_id):
    uid = request.current_user.id
    img = db_session.query(EncryptedImage).filter_by(id=image_id).first()
    if not img:
        return jsonify({'error': 'Not found'}), 404
    if img.sender_id != uid and img.recipient_id != uid and img.owner_id != uid:
        _log_event('UNAUTHORIZED_IMAGE_DELETE', user_id=uid, result='FAILURE', severity='WARNING')
        return jsonify({'error': 'Forbidden'}), 403

    blob_path = os.path.join(BLOB_DIR, img.blob_filename)
    if os.path.isfile(blob_path):
        os.remove(blob_path)    # Securely remove encrypted blob
    img.status = 'deleted'
    db_session.commit()
    _log_event('IMAGE_DELETED', user_id=uid)
    return jsonify({'message': 'Deleted'}), 200


# ─────────────────────────────────────────────────────────────────────────────
#  Transfer Request Handshake Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/transfer-requests', methods=['POST'])
@require_auth
def create_transfer_request():
    data = request.get_json(silent=True) or {}
    recipient_name = str(data.get('recipient', '')).strip().lower()
    if not recipient_name:
        return jsonify({'error': 'Recipient username is required'}), 400
    target = db_session.query(User).filter_by(username=recipient_name, status='active').first()
    if not target:
        return jsonify({'error': 'Recipient not found'}), 404
    if target.id == request.current_user.id:
        return jsonify({'error': 'Cannot send transfer request to yourself'}), 400

    existing = db_session.query(TransferRequest).filter(
        or_(
            (TransferRequest.sender_id == request.current_user.id) & (TransferRequest.recipient_id == target.id),
            (TransferRequest.sender_id == target.id) & (TransferRequest.recipient_id == request.current_user.id)
        )
    ).first()
    if existing:
        if existing.status == 'accepted':
            return jsonify({'message': 'Transfer already accepted', 'status': 'accepted', 'request_id': existing.id}), 200
        elif existing.status == 'pending':
            return jsonify({'message': 'Transfer request already pending', 'status': 'pending', 'request_id': existing.id}), 200
        else:
            existing.sender_id = request.current_user.id
            existing.recipient_id = target.id
            existing.status = 'pending'
            existing.updated_at = datetime.datetime.utcnow()
            db_session.commit()
            _log_event('TRANSFER_REQUEST_SENT', user_id=request.current_user.id)
            return jsonify({'message': 'Transfer request sent', 'status': 'pending', 'request_id': existing.id}), 201

    req = TransferRequest(sender_id=request.current_user.id, recipient_id=target.id, status='pending')
    db_session.add(req)
    db_session.commit()
    _log_event('TRANSFER_REQUEST_SENT', user_id=request.current_user.id)
    return jsonify({'message': 'Transfer request sent', 'status': 'pending', 'request_id': req.id}), 201


@app.route('/api/transfer-requests', methods=['GET'])
@require_auth
def list_transfer_requests():
    uid = request.current_user.id
    reqs = db_session.query(TransferRequest).filter(
        or_(TransferRequest.sender_id == uid, TransferRequest.recipient_id == uid)
    ).order_by(TransferRequest.updated_at.desc()).all()

    user_ids = {r.sender_id for r in reqs} | {r.recipient_id for r in reqs}
    users_map = {u.id: u.username for u in db_session.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}

    result = []
    for r in reqs:
        direction = 'incoming' if r.recipient_id == uid else 'outgoing'
        peer_username = users_map.get(r.sender_id if direction == 'incoming' else r.recipient_id, 'unknown')
        result.append({
            'id': r.id,
            'direction': direction,
            'status': r.status,
            'peer_username': peer_username,
            'created_at': r.created_at.isoformat(),
            'updated_at': r.updated_at.isoformat() if r.updated_at else r.created_at.isoformat()
        })
    return jsonify(result), 200


@app.route('/api/transfer-requests/<req_id>/accept', methods=['POST'])
@require_auth
def accept_transfer_request(req_id):
    req = db_session.query(TransferRequest).filter_by(id=req_id, recipient_id=request.current_user.id).first()
    if not req:
        return jsonify({'error': 'Transfer request not found'}), 404
    req.status = 'accepted'
    db_session.commit()
    _log_event('TRANSFER_REQUEST_ACCEPTED', user_id=request.current_user.id)
    return jsonify({'message': 'Transfer request accepted', 'status': 'accepted'}), 200


@app.route('/api/transfer-requests/<req_id>/decline', methods=['POST'])
@require_auth
def decline_transfer_request(req_id):
    req = db_session.query(TransferRequest).filter_by(id=req_id, recipient_id=request.current_user.id).first()
    if not req:
        return jsonify({'error': 'Transfer request not found'}), 404
    req.status = 'declined'
    db_session.commit()
    _log_event('TRANSFER_REQUEST_DECLINED', user_id=request.current_user.id)
    return jsonify({'message': 'Transfer request declined', 'status': 'declined'}), 200


# ─────────────────────────────────────────────────────────────────────────────
#  Security / Audit
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/security/events', methods=['GET'])
@require_auth
def security_events():
    evts = (
        db_session.query(SecurityEvent)
        .filter_by(user_id=request.current_user.id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(20).all()
    )
    return jsonify([{
        'id': e.id, 'event_type': e.event_type,
        'result': e.result, 'severity': e.severity,
        'created_at': e.created_at.isoformat()
    } for e in evts]), 200


@app.route('/api/security/events', methods=['DELETE'])
@require_auth
def clear_security_events():
    db_session.query(SecurityEvent).filter_by(user_id=request.current_user.id).delete(synchronize_session=False)
    db_session.commit()
    _log_event('AUDIT_LOG_CLEARED', user_id=request.current_user.id)
    return jsonify({'message': 'Audit log cleared'}), 200


# ─────────────────────────────────────────────────────────────────────────────
#  Static Frontend (SPA catch-all)
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    full = os.path.join(app.static_folder, path)
    if path and os.path.isfile(full):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')


# ─────────────────────────────────────────────────────────────────────────────
#  Error Handlers
# ─────────────────────────────────────────────────────────────────────────────
@app.errorhandler(413)
def too_large(_):
    return jsonify({'error': 'Request entity too large'}), 413

@app.errorhandler(404)
def not_found(_):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(_):
    return jsonify({'error': 'Internal server error'}), 500

@app.teardown_appcontext
def remove_session(_):
    db_session.remove()


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='127.0.0.1')
