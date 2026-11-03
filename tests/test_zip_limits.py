"""zip 资源上限回归（M-03 遗留项）：条目数、总解压量、单条目、压缩比四类超限。"""

from __future__ import annotations

import os
import subprocess
import time
import zipfile
from pathlib import Path

import pytest

from src.config import PROJECT_ROOT
from src.replay import ZipLimits, unpacked

# 既有真实包（只读回归；不存在时跳过，避免把仓库产物变成硬依赖）
REAL_PACKAGE = PROJECT_ROOT / "var" / "v6-3000" / "packages" / "run-20261102T225122-b335a25d.zip"


def _write_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def test_zip_entry_count_limit(tmp_path):
    path = _write_zip(tmp_path / "many.zip",
                      {f"m{i}.txt": b"x" for i in range(10)})
    with pytest.raises(ValueError, match="条目数"):
        with unpacked(path, limits=ZipLimits(max_entries=5)):
            pass


def test_zip_total_uncompressed_limit(tmp_path):
    path = _write_zip(tmp_path / "total.zip", {
        "a.bin": b"A" * (2 * 1024 * 1024),
        "b.bin": b"B" * (2 * 1024 * 1024),
    })
    with pytest.raises(ValueError, match="总大小"):
        with unpacked(path, limits=ZipLimits(
                max_entries=10,
                max_total_uncompressed_bytes=1024 * 1024,
                max_member_uncompressed_bytes=8 * 1024 * 1024,
                max_compression_ratio=1_000_000)):
            pass


def test_zip_single_member_limit(tmp_path):
    path = _write_zip(tmp_path / "single.zip", {
        "a.bin": b"A" * (2 * 1024 * 1024),
    })
    with pytest.raises(ValueError, match="单条目"):
        with unpacked(path, limits=ZipLimits(
                max_entries=10,
                max_total_uncompressed_bytes=8 * 1024 * 1024,
                max_member_uncompressed_bytes=1024 * 1024,
                max_compression_ratio=1_000_000)):
            pass


def test_zip_compression_ratio_limit(tmp_path):
    path = _write_zip(tmp_path / "ratio.zip", {
        "bomb.bin": b"A" * (2 * 1024 * 1024),
    })
    with pytest.raises(ValueError, match="压缩比"):
        with unpacked(path, limits=ZipLimits(
                max_entries=10,
                max_total_uncompressed_bytes=8 * 1024 * 1024,
                max_member_uncompressed_bytes=8 * 1024 * 1024,
                max_compression_ratio=50)):
            pass


def _write_dir_package(path: Path, files: dict[str, bytes] | None = None,
                       *, manifest: bytes = b"{}") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "manifest.json").write_bytes(manifest)
    for name, data in (files or {}).items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return path


def test_directory_entry_count_limit(tmp_path):
    pkg = _write_dir_package(tmp_path / "dir-many",
                             {f"m{i}.txt": b"x" for i in range(9)})
    with pytest.raises(ValueError, match="TOO_MANY_ENTRIES"):
        with unpacked(pkg, limits=ZipLimits(max_entries=5)):
            pass


def test_directory_single_member_limit(tmp_path):
    pkg = _write_dir_package(tmp_path / "dir-member",
                             {"big.bin": b"A" * (2 * 1024 * 1024)})
    with pytest.raises(ValueError, match="MEMBER_TOO_LARGE"):
        with unpacked(pkg, limits=ZipLimits(
                max_entries=10,
                max_total_uncompressed_bytes=8 * 1024 * 1024,
                max_member_uncompressed_bytes=1024 * 1024)):
            pass


def test_directory_total_bytes_limit(tmp_path):
    pkg = _write_dir_package(tmp_path / "dir-total", {
        "a.bin": b"A" * (2 * 1024 * 1024),
        "b.bin": b"B" * (2 * 1024 * 1024),
    })
    with pytest.raises(ValueError, match="TOTAL_TOO_LARGE"):
        with unpacked(pkg, limits=ZipLimits(
                max_entries=10,
                max_total_uncompressed_bytes=1024 * 1024,
                max_member_uncompressed_bytes=8 * 1024 * 1024)):
            pass


def test_directory_depth_limit(tmp_path):
    deep = "/".join(f"d{i}" for i in range(1, 10))
    pkg = _write_dir_package(tmp_path / "dir-deep", {f"{deep}/deep.txt": b"x"})
    with pytest.raises(ValueError, match="DEPTH_TOO_DEEP"):
        with unpacked(pkg, limits=ZipLimits(max_entries=20, max_depth=3)):
            pass


def test_directory_exact_limits_still_pass(tmp_path):
    pkg = _write_dir_package(tmp_path / "dir-boundary", {"one.txt": b"x"})
    # manifest 2 字节 + one.txt 1 字节；条目数 2；恰好等于上限应放行。
    with unpacked(pkg, limits=ZipLimits(
            max_entries=2,
            max_total_uncompressed_bytes=3,
            max_member_uncompressed_bytes=2)):
        assert (pkg / "manifest.json").is_file()


def test_directory_symlink_is_rejected(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    pkg = _write_dir_package(tmp_path / "dir-symlink")
    link = pkg / "link.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"当前平台/权限不能创建符号链接：{exc}")
    with pytest.raises(ValueError, match="SYMLINK_REJECTED"):
        with unpacked(pkg, limits=ZipLimits()):
            pass


@pytest.mark.skipif(os.name != "nt", reason="Windows junction 专项")
def test_directory_windows_junction_reparse_point_rejected(tmp_path):
    outside = tmp_path / "outside-dir"
    outside.mkdir()
    (outside / "x.txt").write_text("outside", encoding="utf-8")
    pkg = _write_dir_package(tmp_path / "dir-junction")
    link = pkg / "linkdir"
    proc = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip(f"当前权限不能创建 junction：{proc.stderr.strip()}")
    with pytest.raises(ValueError, match="REPARSE_POINT_REJECTED"):
        with unpacked(pkg, limits=ZipLimits()):
            pass


def test_directory_hardlink_is_rejected(tmp_path):
    pkg = _write_dir_package(tmp_path / "dir-hardlink", {"target.txt": b"x"})
    try:
        os.link(pkg / "target.txt", pkg / "hard.txt")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"当前平台/权限不能创建硬链接：{exc}")
    with pytest.raises(ValueError, match="HARDLINK_REJECTED"):
        with unpacked(pkg, limits=ZipLimits()):
            pass


def test_real_package_still_extracts_under_default_limits():
    if not REAL_PACKAGE.is_file():
        pytest.skip(f"既有真实包不存在：{REAL_PACKAGE}")
    started = time.perf_counter()
    with unpacked(REAL_PACKAGE, limits=ZipLimits()) as d:
        assert (d / "manifest.json").is_file()
        assert (d / "inputs" / "manifest.json").is_file()
        im = (d / "inputs" / "manifest.json").read_text(encoding="utf-8")
        assert '"entries"' in im
    assert time.perf_counter() - started < 10, "正常真实包解包不应被资源上限误伤"
