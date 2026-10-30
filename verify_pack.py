#!/usr/bin/env python3
"""Read-only delivery check. Standard library only; no product imports or API calls.

Git: supply the full commit from the release announcement. Extracted archive:
supply the RELEASE_MANIFEST.json SHA-256 from a separately trusted channel.
The checker reports byte identity and inventory consistency, not publisher trust.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys


CORE_MANIFEST = "offline_qualification_v1/SOURCE_MANIFEST.json"
CORE_SHA256 = "adeca462c152a7ee34c4bdee0f1f9b3833adab6b1aa5ae6e110d2ae58a42c6cb"
RELEASE = "RELEASE_MANIFEST.json"
PACKAGE = "PACKAGE_MANIFEST.json"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)


def linked(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400)


def verify(root, expected_commit=None, expected_manifest=None):
    root = Path(os.path.abspath(str(root)))
    issues = []
    checks = {}
    result = {"schema": "H56_PACK_VERIFICATION_V1", "root": str(root),
              "checks": checks, "issues": issues,
              "excluded_from_inventory": [".git (at checkout root only)"],
              "scope": "Read-only bytes, inventory, Git identity and 139-member closure; no runtime or license approval."}

    def error(code, path=None, **detail):
        issues.append(dict(code=code, **({"path": path} if path else {}), **detail))

    def git(*args):
        env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
        proc = subprocess.run(["git", "-C", str(root), *args], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode:
            raise ValueError("git command failed: " + args[0])
        return proc.stdout

    def entries(obj, size_key, label, key="files"):
        data = obj.get(key)
        if not isinstance(data, list):
            raise ValueError(label + ": missing entry list")
        found = {}
        names = set()
        for item in data:
            if not isinstance(item, dict):
                raise ValueError(label + ": invalid entry")
            name = item.get("path")
            if (not isinstance(name, str) or not name or "\\" in name
                    or ":" in name or PurePosixPath(name).is_absolute()
                    or any(p in ("", ".", "..", ".git") or p.endswith((".", " "))
                           for p in name.split("/"))):
                raise ValueError(label + ": unsafe member path")
            if name.casefold() in names:
                raise ValueError(label + ": duplicate/case-colliding path " + name)
            size, digest = item.get(size_key), item.get("sha256")
            if (type(size) is not int or size < 0 or not isinstance(digest, str)
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
                raise ValueError(label + ": invalid size/hash " + name)
            names.add(name.casefold())
            found[name] = (size, digest)
        return found

    actual = {}
    try:
        if linked(root) or not root.is_dir():
            raise ValueError("root must be a real directory, not a reparse point")
        for base, dirs, files in os.walk(str(root), followlinks=False):
            parent = Path(base)
            for name in list(dirs):
                path = parent / name
                rel = path.relative_to(root).as_posix()
                if parent == root and name == ".git":
                    dirs.remove(name)
                elif linked(path):
                    dirs.remove(name)
                    error("REPARSE_POINT", rel)
            for name in files:
                path = parent / name
                rel = path.relative_to(root).as_posix()
                if rel == ".git":
                    continue
                if linked(path) or not stat.S_ISREG(path.lstat().st_mode):
                    error("NON_REGULAR_MEMBER", rel)
                    continue
                raw = path.read_bytes()
                actual[rel] = (len(raw), sha(raw))
        checks["actual_files"] = len(actual)
        release_raw = (root / RELEASE).read_bytes() if RELEASE in actual else None
        if release_raw is None:
            raise ValueError("release manifest missing")
        checks["release_manifest_sha256"] = sha(release_raw)

        if (root / ".git").exists():
            result["carrier"] = "git_checkout"
            top = Path(os.fsdecode(git("rev-parse", "--show-toplevel")).strip())
            if os.path.normcase(str(top.absolute())) != os.path.normcase(str(root)):
                raise ValueError("root is not the Git work-tree root")
            head = git("rev-parse", "HEAD").decode("ascii").strip()
            checks["head"] = head
            checks["expected_commit"] = expected_commit
            if not expected_commit:
                error("EXPECTED_COMMIT_REQUIRED")
            elif head != expected_commit:
                error("HEAD_MISMATCH", expected=expected_commit, actual=head)
            status = git("status", "--porcelain=v1", "--untracked-files=all").decode("utf-8", "replace")
            checks["working_tree_clean"] = not status
            if status:
                error("DIRTY_WORK_TREE", status=status)
            if git("show", "HEAD:" + RELEASE) != release_raw:
                error("RELEASE_MANIFEST_NOT_AT_HEAD", RELEASE)
            tracked = set(git("ls-files", "-z").decode("utf-8").strip("\0").split("\0"))
        else:
            result["carrier"] = "extracted_archive"
            checks["head"] = None
            checks["working_tree_clean"] = None
            tracked = None
            if expected_commit:
                error("GIT_METADATA_REQUIRED_FOR_COMMIT_CHECK")
            if not expected_manifest:
                error("EXPECTED_MANIFEST_SHA256_REQUIRED")

        if expected_manifest and sha(release_raw) != expected_manifest:
            error("RELEASE_MANIFEST_SHA256_MISMATCH")
        release = strict_json(release_raw)
        package = strict_json((root / PACKAGE).read_bytes()) if PACKAGE in actual else {}
        core_raw = (root / CORE_MANIFEST).read_bytes() if CORE_MANIFEST in actual else b"{}"
        core = strict_json(core_raw)
        if any(not isinstance(obj, dict) for obj in (release, package, core)):
            raise ValueError("manifests must be JSON objects")
        rel_entries = entries(release, "bytes", RELEASE)
        pkg_entries = entries(package, "size", PACKAGE)
        core_entries = entries(core, "size", CORE_MANIFEST, "runtime_required")
        expected_files = set(rel_entries) | {RELEASE}
        if RELEASE in rel_entries or PACKAGE not in rel_entries:
            error("RELEASE_SELF_EXCLUSION_INVALID")
        if (set(pkg_entries) != expected_files - {RELEASE, PACKAGE}
                or package.get("excludes") != [PACKAGE, RELEASE]):
            error("PACKAGE_MEMBERSHIP_DISAGREES")
        if (type(package.get("member_count")) is not int
                or package["member_count"] != len(pkg_entries)
                or type(package.get("candidate_file_count")) is not int
                or package["candidate_file_count"] != len(expected_files)):
            error("PACKAGE_COUNT_MISMATCH")
        if not release.get("candidate_id") or release.get("candidate_id") != package.get("candidate_id"):
            error("CANDIDATE_ID_DISAGREES")
        checks["candidate_id"] = release.get("candidate_id")
        checks["expected_files"] = len(expected_files)
        for name in sorted(expected_files - set(actual)):
            error("MISSING_FILE", name)
        for name in sorted(set(actual) - expected_files):
            error("EXTRA_FILE", name)
        if tracked is not None and tracked != expected_files:
            error("GIT_TRACKED_MEMBERSHIP_DISAGREES",
                  missing=sorted(expected_files - tracked), extra=sorted(tracked - expected_files))
        for label, group in (("RELEASE", rel_entries), ("PACKAGE", pkg_entries), ("CORE", core_entries)):
            for name, identity in sorted(group.items()):
                if name not in actual:
                    error(label + "_MEMBER_MISSING", name)
                elif actual[name] != identity:
                    error(label + "_MEMBER_MISMATCH", name)
        tagged = {item["path"] for item in release["files"] if item.get("computation_closure") is True}
        if (sha(core_raw) != CORE_SHA256 or release.get("source_manifest_sha256") != CORE_SHA256
                or type(release.get("computation_members")) is not int
                or release["computation_members"] != 139 or len(core_entries) != 139
                or tagged != set(core_entries) or not set(core_entries) <= set(rel_entries)):
            error("ORIGINAL_CORE_CLOSURE_DISAGREES")
        checks["core_members"] = len(core_entries)
        checks["core_bytes"] = sum(size for size, _ in core_entries.values())
        checks["core_manifest_sha256"] = sha(core_raw)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        error("VERIFICATION_ERROR", detail=str(exc))
    result["verdict"] = "PASS" if not issues else "FAIL"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).absolute().parent)
    parser.add_argument("--expected-commit", help="Full commit obtained from the release announcement")
    parser.add_argument("--expected-manifest-sha256", help="Trusted external RELEASE_MANIFEST.json SHA-256 (required without .git)")
    parser.add_argument("--json", action="store_true", help="Print the complete result JSON to stdout")
    args = parser.parse_args()
    for name, pattern in (("expected_commit", r"[0-9a-f]{40}|[0-9a-f]{64}"),
                          ("expected_manifest_sha256", r"[0-9a-f]{64}")):
        value = getattr(args, name)
        if value is not None and re.fullmatch(pattern, value) is None:
            parser.error(name + " must be a full lowercase hexadecimal digest")
    result = verify(args.root, args.expected_commit, args.expected_manifest_sha256)
    if args.json:
        print(json.dumps(result, ensure_ascii=True, indent=2))
    else:
        print("H56 pack: " + result["verdict"])
        print(json.dumps(result["checks"], ensure_ascii=True, indent=2))
        for issue in result["issues"]:
            print(json.dumps(issue, ensure_ascii=True))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
