"""数据库初始化与会话。"""
from __future__ import annotations
import datetime as dt
import contextlib
from typing import Iterator

from sqlmodel import Session, create_engine, select, SQLModel

from . import config
from .models import KeyEntry, AIToken, PendingConnection, Setting

engine = create_engine(
    f"sqlite:///{config.DB_FILE}",
    echo=False,
    connect_args={"check_same_thread": False},
)


@contextlib.contextmanager
def get_session() -> Iterator[Session]:
    with Session(engine) as s:
        yield s


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


# ---------- 密码哈希（Settings 表里存 LOGIN_PASSWORD_HASH） ----------

SETTING_PWD_HASH = "login_password_hash"


def get_password_hash() -> str | None:
    with get_session() as s:
        row = s.get(Setting, SETTING_PWD_HASH)
        return row.value if row else None


def set_password_hash(h: str) -> None:
    with get_session() as s:
        row = s.get(Setting, SETTING_PWD_HASH)
        if row:
            row.value = h
        else:
            s.add(Setting(key=SETTING_PWD_HASH, value=h))
        s.commit()


# ---------- KeyEntry ----------

def list_keys() -> list[KeyEntry]:
    with get_session() as s:
        return list(s.exec(select(KeyEntry).order_by(KeyEntry.name)).all())


def get_key(name: str) -> KeyEntry | None:
    with get_session() as s:
        return s.exec(select(KeyEntry).where(KeyEntry.name == name)).first()


def upsert_key(name: str, encrypted_value: str) -> None:
    with get_session() as s:
        row = s.exec(select(KeyEntry).where(KeyEntry.name == name)).first()
        if row:
            row.value = encrypted_value
            row.updated_at = dt.datetime.now(dt.timezone.utc)
        else:
            s.add(KeyEntry(name=name, value=encrypted_value))
        s.commit()


def delete_key(name: str) -> bool:
    with get_session() as s:
        row = s.exec(select(KeyEntry).where(KeyEntry.name == name)).first()
        if row:
            s.delete(row)
            s.commit()
            return True
        return False


# ---------- AIToken ----------

def get_token_by_hash(token_hash: str) -> AIToken | None:
    with get_session() as s:
        return s.exec(select(AIToken).where(AIToken.token_hash == token_hash)).first()


def list_tokens() -> list[AIToken]:
    with get_session() as s:
        return list(s.exec(select(AIToken).order_by(AIToken.created_at.desc())).all())


def create_token(client_name: str, token_hash: str, expires_at: dt.datetime,
                 ip: str | None) -> AIToken:
    with get_session() as s:
        row = AIToken(
            client_name=client_name,
            token_hash=token_hash,
            expires_at=expires_at,
            last_ip=ip,
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        return row


def update_token(row: AIToken, expires_at: dt.datetime | None = None,
                 last_used_at: dt.datetime | None = None,
                 last_ip: str | None = None, status: str | None = None) -> None:
    with get_session() as s:
        db_row = s.get(AIToken, row.id)
        if expires_at is not None:
            db_row.expires_at = expires_at
        if last_used_at is not None:
            db_row.last_used_at = last_used_at
        if last_ip is not None:
            db_row.last_ip = last_ip
        if status is not None:
            db_row.status = status
        s.add(db_row)
        s.commit()


def delete_token(token_id: int) -> bool:
    with get_session() as s:
        row = s.get(AIToken, token_id)
        if row:
            s.delete(row)
            s.commit()
            return True
        return False


# ---------- PendingConnection ----------

def create_pending(connect_id: str, client_name: str, ip: str | None,
                   ua: str | None) -> PendingConnection:
    with get_session() as s:
        row = PendingConnection(connect_id=connect_id, client_name=client_name,
                                ip=ip, ua=ua)
        s.add(row)
        s.commit()
        s.refresh(row)
        return row


def get_pending(connect_id: str) -> PendingConnection | None:
    with get_session() as s:
        return s.exec(select(PendingConnection).where(
            PendingConnection.connect_id == connect_id)).first()


def list_pending() -> list[PendingConnection]:
    with get_session() as s:
        return list(s.exec(select(PendingConnection)
                           .where(PendingConnection.status == "pending")
                           .order_by(PendingConnection.created_at.desc())).all())


def set_pending_status(pending_id: int, status: str) -> None:
    with get_session() as s:
        row = s.get(PendingConnection, pending_id)
        if row:
            row.status = status
            s.add(row)
            s.commit()


# ---------- 启动时初始化 ----------

def bootstrap() -> None:
    init_db()
