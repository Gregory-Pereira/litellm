"""Tests for scripts/verify_image_signature.py, the cosign wrapper behind image release verification.

These tests use a stub cosign binary and digest-pinned references, so they never touch the network
or the real registry. Real signature verification of a published release is run manually and
recorded in the PR, not here.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest

import verify_image_signature as verifier

ROOT: Final = Path(__file__).resolve().parents[2]
SCRIPT: Final = ROOT / "scripts" / "verify_image_signature.py"
DIGEST: Final = "a" * 64
PINNED_REF: Final = f"ghcr.io/berriai/litellm@sha256:{DIGEST}"

STUB_COSIGN: Final = """\
#!{python}
import json
import sys

assert "--key" in sys.argv and "--output" in sys.argv and sys.argv[-1].startswith("ghcr.io/berriai/litellm@sha256:")
if {fail}:
    sys.stderr.write("no matching signatures: error verifying bundle")
    sys.exit(1)
ref = sys.argv[-1]
print(json.dumps([{{
    "critical": {{
        "identity": {{"docker-reference": "ghcr.io/berriai/litellm"}},
        "image": {{"docker-manifest-digest": ref.split("@")[1]}},
        "type": "cosign container image signature",
    }},
    "optional": {{}},
}}]))
"""


def _stub_cosign_dir(tmp_path: Path, fail: bool) -> Path:
    stub_dir: Final = tmp_path / ("cosign-fail-bin" if fail else "cosign-bin")
    stub_dir.mkdir()
    stub: Final = stub_dir / "cosign"
    stub.write_text(STUB_COSIGN.format(python=sys.executable, fail=fail))
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return stub_dir


def _run(image: str, key: str, path: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), image, "--key", key],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PATH": f"{path}:{os.environ['PATH']}"},
    )


def _key_file(tmp_path: Path) -> str:
    key: Final = tmp_path / "trusted.pub"
    key.write_text("-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n")
    return str(key)


def test_signed_digest_pinned_image_verifies(tmp_path: Path) -> None:
    result: Final = _run(PINNED_REF, _key_file(tmp_path), str(_stub_cosign_dir(tmp_path, fail=False)))
    assert result.returncode == 0, result.stderr
    assert f"verified {PINNED_REF}" in result.stdout
    assert f"signature covers digest sha256:{DIGEST}" in result.stdout


def test_unsigned_image_fails(tmp_path: Path) -> None:
    result: Final = _run(PINNED_REF, _key_file(tmp_path), str(_stub_cosign_dir(tmp_path, fail=True)))
    assert result.returncode == 1
    assert "no matching signatures" in result.stderr
    assert "exit code 1" in result.stderr


def test_missing_cosign_fails(tmp_path: Path) -> None:
    empty_dir: Final = tmp_path / "empty-bin"
    empty_dir.mkdir()
    result: Final = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), PINNED_REF, "--key", _key_file(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": str(empty_dir)},
    )
    assert result.returncode == 1
    assert "cosign is not installed" in result.stderr


def test_unsupported_image_reference_fails(tmp_path: Path) -> None:
    result: Final = _run(
        "ghcr.io/berriai/litellm-database:v1.106.4", _key_file(tmp_path), str(_stub_cosign_dir(tmp_path, fail=False))
    )
    assert result.returncode == 1
    assert "Unsupported image reference" in result.stderr


def test_malformed_digest_fails(tmp_path: Path) -> None:
    result: Final = _run(
        "ghcr.io/berriai/litellm@sha256:short", _key_file(tmp_path), str(_stub_cosign_dir(tmp_path, fail=False))
    )
    assert result.returncode == 1
    assert "Malformed digest" in result.stderr


def test_unpinned_key_url_fails(tmp_path: Path) -> None:
    result: Final = _run(
        PINNED_REF,
        "https://raw.githubusercontent.com/BerriAI/litellm/main/cosign.pub",
        str(_stub_cosign_dir(tmp_path, fail=False)),
    )
    assert result.returncode == 1
    assert "Unsupported key reference" in result.stderr


def test_parse_image_ref_accepts_tag_and_digest() -> None:
    assert verifier.parse_image_ref("ghcr.io/berriai/litellm:v1.106.4") == ("v1.106.4", None)
    assert verifier.parse_image_ref(PINNED_REF) == (None, f"sha256:{DIGEST}")


@pytest.mark.parametrize("ref", ["ghcr.io/other/image:v1", "ghcr.io/berriai/litellm", "ghcr.io/berriai/litellm:v!.106"])
def test_parse_image_ref_rejects_invalid_references(ref: str) -> None:
    with pytest.raises(SystemExit):
        verifier.parse_image_ref(ref)


def test_verified_digest_requires_a_consistent_payload() -> None:
    payload: Final = json.dumps([{"critical": {"image": {"docker-manifest-digest": f"sha256:{DIGEST}"}}}])
    assert verifier.verified_digest(payload, PINNED_REF) == f"sha256:{DIGEST}"
    with pytest.raises(SystemExit):
        verifier.verified_digest("[]", PINNED_REF)
    with pytest.raises(SystemExit):
        verifier.verified_digest("not json", PINNED_REF)


def test_main_rejects_signature_covering_a_different_digest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key: Final = tmp_path / "trusted.pub"
    key.write_text("-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n")
    monkeypatch.setattr(sys, "argv", ["verify_image_signature.py", PINNED_REF, "--key", str(key)])
    monkeypatch.setattr(verifier, "run_cosign", lambda *_: ("[]", "0" * 64))
    with pytest.raises(SystemExit) as excinfo:
        verifier.main()
    assert "no usable signature payload" in str(excinfo.value)


def test_main_verifies_a_resolved_tag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    key: Final = tmp_path / "trusted.pub"
    key.write_text("-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n")
    payload: Final = json.dumps([{"critical": {"image": {"docker-manifest-digest": f"sha256:{DIGEST}"}}}])
    monkeypatch.setattr(
        sys, "argv", ["verify_image_signature.py", "ghcr.io/berriai/litellm:v1.106.4", "--key", str(key)]
    )
    monkeypatch.setattr(verifier, "resolve_digest", lambda *_: f"sha256:{DIGEST}")
    monkeypatch.setattr(verifier, "run_cosign", lambda *_: (payload, "0" * 64))
    verifier.main()
    output: Final = capsys.readouterr().out
    assert f"verified {PINNED_REF}" in output
    assert f"signature covers digest sha256:{DIGEST}" in output


def test_main_fails_when_the_signature_covers_another_digest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key: Final = tmp_path / "trusted.pub"
    key.write_text("-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n")
    payload: Final = json.dumps([{"critical": {"image": {"docker-manifest-digest": f"sha256:{'b' * 64}"}}}])
    monkeypatch.setattr(
        sys, "argv", ["verify_image_signature.py", "ghcr.io/berriai/litellm:v1.106.4", "--key", str(key)]
    )
    monkeypatch.setattr(verifier, "resolve_digest", lambda *_: f"sha256:{DIGEST}")
    monkeypatch.setattr(verifier, "run_cosign", lambda *_: (payload, "0" * 64))
    with pytest.raises(SystemExit) as excinfo:
        verifier.main()
    assert "does not match the digest resolved from the registry" in str(excinfo.value)
