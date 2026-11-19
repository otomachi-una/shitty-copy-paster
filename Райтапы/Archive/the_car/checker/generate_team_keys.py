#!/usr/bin/env python3
"""Create or recover per-team checker keys from a team_id,host CSV manifest."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
from pathlib import Path
import tempfile

if __package__:
    from .generate_keys import (
        REPOSITORY, TEAM_ID, Ed25519PrivateKey, Encoding, NoEncryption,
        PrivateFormat, PublicFormat, _load_keys,
    )
else:
    from generate_keys import (
        REPOSITORY, TEAM_ID, Ed25519PrivateKey, Encoding, NoEncryption,
        PrivateFormat, PublicFormat, _load_keys,
    )


def read_teams(path: Path) -> list[tuple[str, str]]:
    """Validate the whole manifest before touching any key or output file."""
    teams: list[tuple[str, str]] = []
    seen_ids: set[str] = set()
    seen_hosts: set[str] = set()
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.reader(source, strict=True)
        if next(reader, None) != ["team_id", "host"]:
            raise ValueError("teams CSV must start with the header team_id,host")
        for row in reader:
            if not row:
                continue
            if len(row) != 2:
                raise ValueError(f"teams CSV line {reader.line_num}: expected two columns")
            team_id, host = row
            if TEAM_ID.fullmatch(team_id) is None:
                raise ValueError(f"teams CSV line {reader.line_num}: invalid team_id")
            if (not host or host != host.strip()
                    or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in host)
                    or any(char in host for char in "/\\?#@")):
                raise ValueError(f"teams CSV line {reader.line_num}: host must be an exact hostname or IP, without a URL or whitespace")
            if team_id in seen_ids or host in seen_hosts:
                raise ValueError(f"teams CSV line {reader.line_num}: duplicate team_id or host")
            seen_ids.add(team_id)
            seen_hosts.add(host)
            teams.append((team_id, host))
    if not teams:
        raise ValueError("teams CSV must contain at least one team")
    return teams


def public_env(entry: dict[str, str]) -> str:
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(entry["private_key"], validate=True))
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return f"TEAM_ID={entry['team_id']}\nCHECKER_PUBKEY={base64.b64encode(public).decode('ascii')}\n"


def _atomic_write(path: Path, contents: str, *, replace: bool) -> None:
    """Publish complete files; public files must never replace existing ones."""
    fd, name = tempfile.mkstemp(prefix=".carhack-keys-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.chmod(temporary, 0o644)
            # A same-directory hard link publishes atomically and fails if the
            # destination appeared after preflight. No partial .env is exposed.
            os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def generate_teams(manifest: Path, checker_keys: Path, service_env_dir: Path) -> tuple[int, int]:
    teams = read_teams(manifest)
    keys_path = checker_keys.expanduser().resolve()
    env_dir = service_env_dir.expanduser().resolve()
    if keys_path.is_relative_to(REPOSITORY):
        raise ValueError("private checker keys must be stored outside the entire service repository")
    if keys_path.is_relative_to(env_dir):
        raise ValueError("private checker keys must be stored outside the public service environment directory")
    if keys_path == manifest.resolve():
        raise ValueError("checker keys and teams CSV must use different files")
    env_paths = {team_id: env_dir / f"team-{team_id}.env" for team_id, _ in teams}
    if len({os.path.normcase(str(path.resolve())) for path in env_paths.values()}) != len(teams):
        raise ValueError("team identities produce colliding public environment filenames")
    if any(path.resolve() == keys_path for path in env_paths.values()):
        raise ValueError("checker keys and public service environments must use different files")

    keys_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = keys_path.with_name(keys_path.name + ".lock")
    try:
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("keys file is locked; finish the other generator or remove a stale .lock file") from exc
    try:
        os.close(lock_fd)
        data = _load_keys(keys_path)
        known_teams = {entry["team_id"]: host for host, entry in data.items()}
        # Check all identities and existing public files before generating keys.
        for team_id, host in teams:
            if host in data and data[host]["team_id"] != team_id:
                raise ValueError(f"host for team {team_id} already belongs to a different team")
            if team_id in known_teams and known_teams[team_id] != host:
                raise ValueError(f"team {team_id} already has a key for a different host")
            env_path = env_paths[team_id]
            if env_path.exists():
                if host not in data:
                    raise ValueError(f"public environment for team {team_id} exists without a matching private key")
                if env_path.read_text(encoding="utf-8-sig").splitlines() != public_env(data[host]).splitlines():
                    raise ValueError(f"public environment for team {team_id} differs from its saved key; refusing to overwrite")

        env_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        created = 0
        for team_id, host in teams:
            if host in data:
                continue
            private = Ed25519PrivateKey.generate()
            seed = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            data[host] = {"team_id": team_id, "private_key": base64.b64encode(seed).decode("ascii")}
            created += 1
        if created:
            # Save private keys first: interruption while exporting public files
            # can be recovered by rerunning, without rotating any saved key.
            _atomic_write(keys_path, json.dumps(data, indent=2, sort_keys=True) + "\n", replace=True)
        exported = 0
        for team_id, host in teams:
            env_path = env_paths[team_id]
            if not env_path.exists():
                _atomic_write(env_path, public_env(data[host]), replace=False)
                exported += 1
        return created, exported
    finally:
        lock_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--teams", required=True, type=Path, help="CSV with header team_id,host")
    parser.add_argument("--checker-keys", required=True, type=Path, help="private JSON outside the repository")
    parser.add_argument("--service-env-dir", required=True, type=Path, help="directory for public team-<team_id>.env files")
    args = parser.parse_args()
    try:
        created, exported = generate_teams(args.teams, args.checker_keys, args.service_env_dir)
    except (OSError, ValueError, UnicodeError, csv.Error) as exc:
        parser.exit(1, f"Team key setup failed: {exc}\n")
    print(f"Created {created} key pairs; exported {exported} public environments. Existing keys were preserved; no private key was printed.")


if __name__ == "__main__":
    main()
