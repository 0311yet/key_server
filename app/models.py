"""SQLModel 数据模型。"""
from __future__ import annotations
import datetime as dt
from typing import Optional

from sqlmodel import SQLModel, Field


def _now() -> dt.datetime:
    return dt.datetime.utcnow()


class KeyEntry(SQLModel, table=True):
    """密钥条目。value 字段是加密后的 base64 blob。"""
    __tablename__ = "keys"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    value: str  # 加密 blob
    created_at: dt.datetime = Field(default_factory=_now)
    updated_at: dt.datetime = Field(default_factory=_now)


class AIToken(SQLModel, table=True):
    """已授权 AI 客户端的 token。只存 hash，不存明文。"""
    __tablename__ = "ai_tokens"

    id: Optional[int] = Field(default=None, primary_key=True)
    client_name: str = Field(index=True)
    token_hash: str = Field(index=True, unique=True)  # sha256 hex
    status: str = Field(default="approved")  # approved / revoked
    created_at: dt.datetime = Field(default_factory=_now)
    expires_at: dt.datetime
    last_used_at: Optional[dt.datetime] = Field(default=None)
    last_ip: Optional[str] = Field(default=None)


class PendingConnection(SQLModel, table=True):
    """待审批的 AI 连接申请。"""
    __tablename__ = "pending_connections"

    id: Optional[int] = Field(default=None, primary_key=True)
    connect_id: str = Field(index=True, unique=True)  # 32 字节 hex
    client_name: str
    created_at: dt.datetime = Field(default_factory=_now)
    ip: Optional[str] = Field(default=None)
    ua: Optional[str] = Field(default=None)
    status: str = Field(default="pending")  # pending / approved / denied


class Setting(SQLModel, table=True):
    """通用键值表，存密码哈希之类。"""
    __tablename__ = "settings"

    key: str = Field(primary_key=True)
    value: str
