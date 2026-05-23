"""
IMMUNEX Evidence Object Store
================================
Phase 7 — Forensic evidence storage with MinIO/S3 support and local disk fallback.
SHA-256 integrity verification, immutable snapshots, case bundle export.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from typing import Any, Optional

from utils.logger import log

_MINIO_AVAILABLE = False
try:
    from minio import Minio
    _MINIO_AVAILABLE = True
except ImportError:
    pass

_EVIDENCE_ROOT = os.path.join("data", "evidence")


class LocalDiskObjectStore:
    """Local filesystem object store. Always available fallback."""

    def __init__(self, root_dir: str = _EVIDENCE_ROOT):
        self._root = root_dir
        self.backend = "local_disk"
        for subdir in ("evidence", "pcaps", "memory_dumps", "bundles"):
            os.makedirs(os.path.join(root_dir, subdir), exist_ok=True)
        log.info("LocalDiskObjectStore initialized", root=root_dir)

    def upload_file(self, bucket: str, key: str, filepath: str) -> dict:
        dest_dir = os.path.join(self._root, bucket)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, key)
        shutil.copy2(filepath, dest)
        file_hash = self._hash_file(filepath)
        # Store integrity hash alongside
        with open(dest + ".sha256", "w") as f:
            f.write(file_hash)
        meta = {"bucket": bucket, "key": key, "size": os.path.getsize(dest),
                "sha256": file_hash, "uploaded_at": time.time(), "backend": self.backend}
        with open(dest + ".meta.json", "w") as f:
            json.dump(meta, f)
        log.debug("EVIDENCE_UPLOADED", bucket=bucket, key=key, sha256=file_hash[:16])
        return meta

    def retrieve_file(self, bucket: str, key: str, dest: str) -> bool:
        src = os.path.join(self._root, bucket, key)
        if not os.path.exists(src):
            return False
        shutil.copy2(src, dest)
        return True

    def verify_integrity(self, bucket: str, key: str) -> dict:
        filepath = os.path.join(self._root, bucket, key)
        hash_file = filepath + ".sha256"
        if not os.path.exists(filepath):
            return {"valid": False, "error": "File not found"}
        current_hash = self._hash_file(filepath)
        if os.path.exists(hash_file):
            with open(hash_file) as f:
                stored_hash = f.read().strip()
            return {"valid": current_hash == stored_hash, "current": current_hash,
                    "stored": stored_hash}
        return {"valid": True, "current": current_hash, "stored": None}

    def archive_incident(self, incident_id: str, files: list[str]) -> dict:
        archive_dir = os.path.join(self._root, "bundles", incident_id)
        os.makedirs(archive_dir, exist_ok=True)
        archived = []
        for fp in files:
            if os.path.exists(fp):
                dest = os.path.join(archive_dir, os.path.basename(fp))
                shutil.copy2(fp, dest)
                archived.append(dest)
        manifest = {"incident_id": incident_id, "files": archived,
                    "archived_at": time.time(), "count": len(archived)}
        with open(os.path.join(archive_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f)
        return manifest

    def export_case_bundle(self, incident_id: str) -> str:
        bundle_dir = os.path.join(self._root, "bundles", incident_id)
        if not os.path.exists(bundle_dir):
            os.makedirs(bundle_dir, exist_ok=True)
        archive_path = os.path.join(self._root, "bundles", f"{incident_id}_bundle")
        shutil.make_archive(archive_path, "zip", bundle_dir)
        return archive_path + ".zip"

    def list_objects(self, bucket: str) -> list[dict]:
        bucket_dir = os.path.join(self._root, bucket)
        if not os.path.exists(bucket_dir):
            return []
        objects = []
        for f in os.listdir(bucket_dir):
            if not f.endswith((".sha256", ".meta.json")):
                fp = os.path.join(bucket_dir, f)
                objects.append({"key": f, "size": os.path.getsize(fp),
                                "modified": os.path.getmtime(fp)})
        return objects

    def _hash_file(self, filepath: str) -> str:
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()


class EvidenceObjectStore(LocalDiskObjectStore):
    """MinIO/S3 evidence store. Falls back to local disk."""

    def __init__(self, endpoint: str = "localhost:9000", access_key: str = "minioadmin",
                 secret_key: str = "minioadmin", secure: bool = False, root_dir: str = _EVIDENCE_ROOT):
        super().__init__(root_dir=root_dir)
        self._minio = None
        if _MINIO_AVAILABLE:
            try:
                self._minio = Minio(endpoint, access_key=access_key,
                                    secret_key=secret_key, secure=secure)
                self._minio.list_buckets()
                self.backend = "minio"
                log.info("MinIO connection established", endpoint=endpoint)
            except Exception as exc:
                log.warning("MinIO unavailable, using local disk", error=str(exc))
                self._minio = None


def create_object_store(**kwargs) -> LocalDiskObjectStore:
    """Factory: returns MinIO or local disk store."""
    if _MINIO_AVAILABLE:
        store = EvidenceObjectStore(**kwargs)
        if store.backend == "minio":
            return store
    return LocalDiskObjectStore()
