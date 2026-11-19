#!/usr/bin/env python3
"""Create a distinct checker signing key for one explicitly configured team."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


REPOSITORY = Path(__file__).resolve().parents[1]
TEAM_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("checker keys file contains duplicate JSON fields")
        result[key] = value
    return result


def _load_keys(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("checker keys file must be accessible only to its owner (chmod 600)")
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("checker keys file is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("checker keys file must contain a host-to-key object")
    teams: set[str] = set()
    public_keys: set[bytes] = set()
    for host, entry in data.items():
        if not isinstance(host, str) or not host or not isinstance(entry, dict) or set(entry) != {"team_id", "private_key"}:
            raise ValueError("checker keys file contains an invalid host entry")
        team = entry.get("team_id")
        encoded = entry.get("private_key")
        if not isinstance(team, str) or TEAM_ID.fullmatch(team) is None or not isinstance(encoded, str):
            raise ValueError("checker keys file contains invalid team/key fields")
        try:
            raw = base64.b64decode(encoded, validate=True)
            private = Ed25519PrivateKey.from_private_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError("checker keys file contains an invalid private key") from exc
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if team in teams or public in public_keys:
            raise ValueError("checker keys file must use distinct team identities and keys")
        teams.add(team)
        public_keys.add(public)
    return data


def generate(host: str, team_id: str, checker_keys: Path, service_env: Path) -> None:
    if not host or host != host.strip() or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in host) or any(character in host for character in "/\\?#@"):
        raise ValueError("host must be an exact checker target hostname or IP address, without a URL or whitespace")
    if TEAM_ID.fullmatch(team_id) is None:
        raise ValueError("team-id must contain 1-64 ASCII letters, digits, dots, underscores or hyphens")
    keys_path = checker_keys.expanduser().resolve()
    env_path = service_env.expanduser().resolve()
    if keys_path.is_relative_to(REPOSITORY):
        raise ValueError("private checker keys must be stored outside the entire service repository")
    if keys_path == env_path:
        raise ValueError("checker keys and public service environment must use different files")
    if env_path.exists():
        raise ValueError("service environment file already exists; refusing to overwrite it")
    keys_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    env_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = keys_path.with_name(keys_path.name + ".lock")
    try:
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("keys file is locked; finish the other generator or remove a stale .lock file") from exc
    temporary: Path | None = None
    created_env = False
    try:
        os.close(lock_fd)
        data = _load_keys(keys_path)
        if host in data:
            raise ValueError("host already has a signing key; refusing to replace it")
        if any(entry["team_id"] == team_id for entry in data.values()):
            raise ValueError("team-id already has a signing key; refusing to reuse its identity")
        private = Ed25519PrivateKey.generate()
        seed = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        data[host] = {"team_id": team_id, "private_key": base64.b64encode(seed).decode("ascii")}
        fd, temporary_name = tempfile.mkstemp(prefix=".checker-keys-", dir=keys_path.parent)
        temporary = Path(temporary_name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            json.dump(data, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        with env_path.open("x", encoding="utf-8", newline="\n") as output:
            created_env = True
            output.write(f"TEAM_ID={team_id}\nCHECKER_PUBKEY={base64.b64encode(public).decode('ascii')}\n")
        os.replace(temporary, keys_path)
        temporary = None
    except BaseException:
        if created_env:
            env_path.unlink(missing_ok=True)
        raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        lock_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="exact target host passed by ForcAD to the checker")
    parser.add_argument("--team-id", required=True, help="distinct identity for this team")
    parser.add_argument("--checker-keys", required=True, type=Path, help="private JSON outside the repository")
    parser.add_argument("--service-env", required=True, type=Path, help="new public TEAM_ID/CHECKER_PUBKEY file")
    args = parser.parse_args()
    try:
        generate(args.host, args.team_id, args.checker_keys, args.service_env)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Key generation failed: {exc}\n")
    print("Created a team key entry and public service environment; no private key was printed.")


if __name__ == "__main__":
    main()
