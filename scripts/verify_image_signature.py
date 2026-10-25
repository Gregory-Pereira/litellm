"""Verify the cosign signature of a published ghcr.io/berriai/litellm image against an explicit trusted key."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Final, NoReturn

IMAGE_REPOSITORY: Final = "ghcr.io/berriai/litellm"
_TOKEN_URL: Final = "https://ghcr.io/token?scope=repository:berriai/litellm:pull&service=ghcr.io"
_MANIFEST_URL: Final = "https://ghcr.io/v2/berriai/litellm/manifests/"
_KEY_URL_PREFIX: Final = "https://raw.githubusercontent.com/BerriAI/litellm/"
_KEY_URL_SUFFIX: Final = "/cosign.pub"
_HEX: Final = frozenset("0123456789abcdef")
_ACCEPT: Final = (
    "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
)
_HTTP_TIMEOUT_SECONDS: Final = 30
_COSIGN_TIMEOUT_SECONDS: Final = 120


def _fail(message: str) -> NoReturn:
    raise SystemExit(message)


def _is_hex(value: str) -> bool:
    return all(char in _HEX for char in value)


def parse_image_ref(ref: str) -> tuple[str | None, str | None]:
    if not ref.startswith(f"{IMAGE_REPOSITORY}:") and not ref.startswith(f"{IMAGE_REPOSITORY}@"):
        _fail(
            f"Unsupported image reference {ref!r}. This check only covers {IMAGE_REPOSITORY} "
            "with an explicit tag or digest, e.g. ghcr.io/berriai/litellm:v1.106.4"
        )
    reference: Final = ref.removeprefix(IMAGE_REPOSITORY)
    if reference.startswith("@sha256:"):
        digest: Final = reference.removeprefix("@")
        if len(digest) == len("sha256:") + 64 and _is_hex(digest.removeprefix("sha256:")):
            return None, digest
        _fail(f"Malformed digest in {ref!r}. Expected @sha256 followed by 64 lowercase hex characters.")
    tag: Final = reference.removeprefix(":")
    if tag and len(tag) <= 127 and all(char.isalnum() or char in "._-" for char in tag):
        return tag, None
    _fail(f"Malformed tag in {ref!r}. Expected a Docker tag of at most 127 alphanumeric, ., _ or - characters.")


def _http_get(url: str, headers: dict[str, str]) -> bytes:
    request: Final = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS) as response:
            return response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        _fail(f"Could not fetch {url}: {exc}")


def _http_head(url: str, headers: dict[str, str]) -> str:
    request: Final = urllib.request.Request(url, headers=headers, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS) as response:
            digest: Final = response.headers.get("Docker-Content-Digest")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        _fail(f"Could not resolve {url} against the registry: {exc}")
    if digest:
        return digest
    _fail(f"The registry did not return a Docker-Content-Digest header for {url}.")


def resolve_digest(image_ref: str, tag: str) -> str:
    token_payload: Final = _http_get(_TOKEN_URL, {})
    try:
        token_doc: Final = json.loads(token_payload)
    except ValueError:
        _fail("The registry token endpoint returned malformed JSON.")
    if not isinstance(token_doc, dict) or not isinstance(token_doc.get("token"), str):
        _fail("The registry token endpoint response lacks a token string.")
    digest: Final = _http_head(
        f"{_MANIFEST_URL}{tag}", {"Authorization": f"Bearer {token_doc['token']}", "Accept": _ACCEPT}
    )
    if digest.startswith("sha256:") and len(digest) == len("sha256:") + 64:
        return digest
    _fail(f"The registry returned a malformed digest {digest!r} for {image_ref}.")


def load_key(key_ref: str) -> tuple[bytes, str]:
    local_path: Final = Path(key_ref)
    if local_path.is_file():
        return local_path.read_bytes(), key_ref
    commit_sha: Final = key_ref[len(_KEY_URL_PREFIX) : -len(_KEY_URL_SUFFIX)]
    is_pinned_url: Final = (
        key_ref.startswith(_KEY_URL_PREFIX)
        and key_ref.endswith(_KEY_URL_SUFFIX)
        and len(commit_sha) == 40
        and _is_hex(commit_sha)
    )
    if not is_pinned_url:
        _fail(
            f"Unsupported key reference {key_ref!r}. Pass a local public key file, or the immutable "
            "commit-pinned URL https://raw.githubusercontent.com/BerriAI/litellm/<full-commit-sha>/cosign.pub"
        )
    return _http_get(key_ref, {}), key_ref


def run_cosign(key_bytes: bytes, pinned_ref: str) -> tuple[str, str]:
    if shutil.which("cosign") is None:
        _fail(
            "cosign is not installed or not on PATH. Install a pinned cosign release from "
            "https://github.com/sigstore/cosign/releases"
        )
    key_sha256: Final = hashlib.sha256(key_bytes).hexdigest()
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".pub") as key_file:
        key_file.write(key_bytes)
        key_file.flush()
        try:
            result: Final = subprocess.run(
                ["cosign", "verify", "--key", key_file.name, "--output", "json", pinned_ref],
                capture_output=True,
                text=True,
                timeout=_COSIGN_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            _fail(f"cosign could not be executed: {exc}")
    if result.returncode != 0:
        _fail(
            f"cosign verification of {pinned_ref} failed with exit code {result.returncode}:\n{result.stderr.strip()}"
        )
    return result.stdout, key_sha256


def verified_digest(stdout: str, pinned_ref: str) -> str:
    try:
        documents: Final = json.loads(stdout)
    except ValueError:
        _fail(f"cosign produced output that is not valid JSON for {pinned_ref}.")
    if not isinstance(documents, list):
        _fail(f"cosign produced unexpected JSON for {pinned_ref}.")
    digests: Final = tuple(
        item["critical"]["image"]["docker-manifest-digest"]
        for item in documents
        if isinstance(item, dict)
        and isinstance(item.get("critical"), dict)
        and isinstance(item["critical"].get("image"), dict)
        and isinstance(item["critical"]["image"].get("docker-manifest-digest"), str)
    )
    if digests and set(digests) == {digests[0]}:
        return digests[0]
    _fail(f"cosign reported no usable signature payload for {pinned_ref}.")


def main() -> None:
    parser: Final = argparse.ArgumentParser(
        description="Verify a published LiteLLM container image signature with cosign."
    )
    parser.add_argument(
        "image",
        help="Image reference, e.g. ghcr.io/berriai/litellm:v1.106.4 or ghcr.io/berriai/litellm@sha256:<digest>",
    )
    parser.add_argument(
        "--key",
        required=True,
        help="Trusted public key: a local file, or https://raw.githubusercontent.com/BerriAI/litellm/<full-commit-sha>/cosign.pub",
    )
    args: Final = parser.parse_args()

    tag, pinned_digest = parse_image_ref(args.image)
    resolved_digest: Final = resolve_digest(args.image, tag) if tag else pinned_digest
    pinned_ref: Final = f"{IMAGE_REPOSITORY}@{resolved_digest}"
    key_bytes, key_source = load_key(args.key)
    stdout, key_sha256 = run_cosign(key_bytes, pinned_ref)
    signed_digest: Final = verified_digest(stdout, pinned_ref)
    if signed_digest != resolved_digest:
        _fail(
            f"cosign verified {pinned_ref} but its signature covers {signed_digest}, which does not match "
            f"the digest resolved from the registry ({resolved_digest})."
        )
    print(f"verified {pinned_ref}")
    print(f"key: {key_source} (sha256 {key_sha256})")
    print(f"signature covers digest {signed_digest}")


if __name__ == "__main__":
    main()
