"""Ed25519 举证包签名/验签与密钥文件工具。

边界：签名只证明“manifest 关键字段 + 审计链头”由一个持有私钥的实体签过。
包内公钥只能做自洽检查；只有外部 pin（--public-key）才能证明来源可信。
私钥不进入包，也不进入任何日志。
"""
from __future__ import annotations

import base64
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from .util import CN_TZ, canonical_json, sha256_hex

SIGNATURE_FIELD = "signature"
SIGNATURE_ALG = "Ed25519"
SIGNATURE_REQUIRED_FIELDS = ("alg", "key_id", "created_at", "public_key_b64",
                             "signature_b64")


def public_key_b64(public_key: bytes) -> str:
    return base64.b64encode(public_key).decode("ascii")


def key_id_for_public_key(public_key: bytes) -> str:
    return "ed25519:" + sha256_hex(public_key)


def _signing_key_class():
    """延迟导入 PyNaCl：无签名/无验签的旧路径不因为缺包而 import 失败。"""
    try:
        from nacl.signing import SigningKey
    except ImportError as exc:
        raise RuntimeError("未安装 PyNaCl，无法签名（见 verify-requirements.txt）") from exc
    return SigningKey


def generate_keypair() -> SigningKey:
    return _signing_key_class().generate()


def _decode_b64(value: str, label: str, length: int | None = None) -> bytes:
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except Exception as exc:
        raise ValueError(f"{label} 不是合法 Base64") from exc
    if length is not None and len(raw) != length:
        raise ValueError(f"{label} 长度应为 {length} 字节，实际 {len(raw)}")
    return raw


def _read_seed(path: Path) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"签名私钥文件不存在：{path}")
    return _decode_b64(path.read_text(encoding="utf-8"), "签名私钥", 32)


def load_signing_key(path: str | Path | None = None) -> SigningKey | None:
    """读取签名私钥：显式文件 > WCA_SIGNING_KEY_FILE > WCA_SIGNING_KEY_B64。"""
    seed = None
    if path is not None:
        seed = _read_seed(Path(path))
    else:
        env_file = os.environ.get("WCA_SIGNING_KEY_FILE")
        if env_file:
            seed = _read_seed(Path(env_file))
        else:
            env_b64 = os.environ.get("WCA_SIGNING_KEY_B64")
            if env_b64:
                seed = _decode_b64(env_b64, "WCA_SIGNING_KEY_B64", 32)
    return _signing_key_class()(seed) if seed is not None else None


def _restrict_private_file(path: Path) -> None:
    """私钥文件只给当前用户：POSIX 0600；Windows 用 icacls 断开继承。"""
    if os.name == "nt":
        user = os.environ.get("USERNAME") or os.getlogin()
        proc = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"无法用 icacls 收紧私钥权限：{proc.stderr.strip() or proc.stdout.strip()}")
    else:
        os.chmod(path, 0o600)


def write_private_key(path: Path | str, key: SigningKey, *, force: bool = False) -> Path:
    """原子写私钥；已存在且未 force 时拒绝覆盖。"""
    target = Path(path)
    if target.exists() and not force:
        raise FileExistsError(f"私钥文件已存在，拒绝覆盖：{target}（确认要覆盖请加 --force）")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp",
                                    dir=str(target.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(base64.b64encode(key.encode()).decode("ascii") + "\n")
        _restrict_private_file(tmp)
        os.replace(tmp, target)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    return target


def write_public_key(path: Path | str, public_key: bytes, *, force: bool = False) -> Path:
    target = Path(path)
    if target.exists() and not force:
        raise FileExistsError(f"公钥文件已存在，拒绝覆盖：{target}（确认要覆盖请加 --force）")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(public_key_b64(public_key) + "\n", encoding="utf-8")
    return target


def load_public_keys(values: list[str] | tuple[str, ...] | None) -> list[bytes]:
    """--public-key 支持文件路径或裸 Base64；可重复传多把（轮换）。"""
    out: list[bytes] = []
    for value in values or []:
        text = str(value)
        path = Path(text)
        raw_text = path.read_text(encoding="utf-8") if path.is_file() else text
        out.append(_decode_b64(raw_text, "公钥", 32))
    return out


def signature_payload(manifest: dict, audit_chain_head: str) -> dict:
    """签名对象；canonical JSON 后跨语言可复算。"""
    triple = manifest.get("triple") or {}
    return {
        "schema": manifest.get("schema"),
        "rule_pack_version": triple.get("rule_pack_version"),
        "input_fingerprint": triple.get("input_fingerprint"),
        "conclusion_digest": triple.get("conclusion_digest"),
        "manifest_checksum": manifest.get("manifest_checksum"),
        "audit_chain_head": audit_chain_head,
    }


def _payload_bytes(manifest: dict, audit_chain_head: str) -> bytes:
    return canonical_json(signature_payload(manifest, audit_chain_head)).encode("utf-8")


def create_signature(manifest: dict, key: SigningKey, audit_chain_head: str) -> dict:
    public = key.verify_key.encode()
    payload = _payload_bytes(manifest, audit_chain_head)
    signature = key.sign(payload).signature
    return {
        "alg": SIGNATURE_ALG,
        "key_id": key_id_for_public_key(public),
        "created_at": datetime.now(CN_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00"),
        "public_key_b64": public_key_b64(public),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def verify_signature(manifest: dict, audit_chain_head: str,
                     pinned_public_keys: list[bytes] | None = None) -> dict:
    """返回 ok/trust/key_id/reason；任何字段/签名/ pin 异常都失败关闭。"""
    block = manifest.get(SIGNATURE_FIELD)
    result = {"present": isinstance(block, dict), "ok": False, "trust": "none",
              "key_id": "", "reason": ""}
    if not isinstance(block, dict):
        result["reason"] = "缺少 manifest.signature"
        return result
    missing = [k for k in SIGNATURE_REQUIRED_FIELDS
               if not isinstance(block.get(k), str) or not block.get(k)]
    if missing:
        result["reason"] = "manifest.signature 缺字段或为空：" + ",".join(missing)
        return result
    if block["alg"] != SIGNATURE_ALG:
        result["reason"] = f"不支持的签名算法：{block['alg']}"
        return result
    try:
        public = _decode_b64(block["public_key_b64"], "public_key_b64", 32)
        signature = _decode_b64(block["signature_b64"], "signature_b64", 64)
    except ValueError as exc:
        result["reason"] = str(exc)
        return result
    key_id = key_id_for_public_key(public)
    result["key_id"] = key_id
    if block["key_id"] != key_id:
        result["reason"] = "key_id 与包内公钥指纹不一致"
        return result
    payload = _payload_bytes(manifest, audit_chain_head)
    if pinned_public_keys:
        matched = [p for p in pinned_public_keys if key_id_for_public_key(p) == key_id]
        if not matched:
            result["reason"] = "签名 key_id 不在外部 pin 公钥集合中"
            return result
        if matched[0] != public:
            result["reason"] = "包内公钥与 pin 公钥字节不一致"
            return result
        public = matched[0]
        result["trust"] = "pinned"
    else:
        result["trust"] = "package-self-check"
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
        VerifyKey(public).verify(payload, signature)
    except BadSignatureError:
        result["reason"] = "Ed25519 签名校验失败（manifest/链头/公钥不匹配或签名被改）"
        return result
    except ImportError:
        result["reason"] = "未安装 PyNaCl，无法验签（见 verify-requirements.txt）"
        return result
    except Exception as exc:
        result["reason"] = f"验签异常：{type(exc).__name__}: {exc}"
        return result
    result["ok"] = True
    result["reason"] = "签名有效"
    return result
