"""Payload asset validation tests (missing/malformed/placeholder/provenance)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import payloads as pay_mod  # noqa: E402

def make_elf(machine=183, e_type=2, klass=2, endian=1, body=b""):
    """Build a structurally valid minimal ELF64 header for tests (not runnable)."""
    e_ident = b"\x7fELF" + bytes([klass, endian, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + e_type.to_bytes(2, "little") + machine.to_bytes(2, "little") + \
        (1).to_bytes(4, "little") + (0).to_bytes(8, "little") * 3 + (64).to_bytes(8, "little") + \
        (0).to_bytes(2, "little") * 5 + (64).to_bytes(2, "little")
    return ehdr + body + b"payload-fixture-bytes" * 16  # >128B total


ELF_FORGERY_FOR_TESTS = make_elf()


def _dir(tmp_path, manifest=None, files=None):
    d = tmp_path
    if manifest is not None:
        (d / pay_mod.MANIFEST_NAME).write_text(json.dumps(manifest))
    for name, blob in (files or {}).items():
        (d / name).write_bytes(blob)
    return str(d)


def test_missing_file(tmp_path):
    a = pay_mod.validate_payload("x.elf", str(tmp_path))
    assert not a.ok and a.reason == "missing_file"


def test_empty_file(tmp_path):
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, files={"x.elf": b""}))
    assert not a.ok and a.reason == "empty_file"


ELF_MAGIC = b"\x7fELF"


def test_oversize(tmp_path):
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, files={"x.elf": b"z" * 200}),
                                 min_bytes=128, max_bytes=150)
    assert not a.ok and a.reason.startswith("bad_size")


def test_placeholder_refused_by_default(tmp_path):
    m = {"x.elf": {"kind": "placeholder"}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, {"x.elf": ELF_FORGERY_FOR_TESTS}))
    assert not a.ok and a.reason == "unverified_placeholder"


def test_placeholder_allowed_when_explicit(tmp_path):
    m = {"x.elf": {"kind": "placeholder"}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, {"x.elf": ELF_FORGERY_FOR_TESTS}),
                                 allow_placeholder=True)
    assert a.ok


def test_no_provenance_refused(tmp_path):
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, {}, {"x.elf": ELF_FORGERY_FOR_TESTS}))
    assert not a.ok and a.reason == "no_provenance_record"


def test_genuine_upstream_accepted(tmp_path):
    import hashlib
    blob = ELF_FORGERY_FOR_TESTS
    m = {"x.elf": {"kind": "upstream", "source_url": "https://github.com/x/releases",
                   "sha256": hashlib.sha256(blob).hexdigest()}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": blob}))
    assert a.ok and a.reason == "genuine_artifact"


def test_non_elf_rejected(tmp_path):
    m = {"x.txt": {"kind": "upstream"}}
    a = pay_mod.validate_payload("non_elf_named_wrong_dir", _dir(tmp_path, m),
                                 allow_placeholder=True)
    assert not a.ok


def test_bad_elf_magic_rejected(tmp_path):
    m = {"x.elf": {"kind": "upstream"}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": b"NOTANELF!" * 32}),
                                 allow_placeholder=True)
    assert not a.ok and a.reason == "not_elf"


def test_sha256_manifest_mismatch(tmp_path):
    blob = ELF_FORGERY_FOR_TESTS
    m = {"x.elf": {"kind": "upstream", "sha256": "00" * 32}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, {"x.elf": blob}))
    assert not a.ok and a.reason == "sha256_mismatch_vs_manifest"


def test_ladder_stops_at_first_rejection(tmp_path):
    m = {"bad.elf": {"kind": "placeholder"}, "good.elf": {"kind": "upstream"}}
    out = pay_mod.validate_ladder(["bad.elf", "good.elf"], _dir(
        tmp_path, m, {"bad.elf": ELF_FORGERY_FOR_TESTS, "good.elf": ELF_FORGERY_FOR_TESTS}))
    assert "bad.elf" in out and not out["bad.elf"].ok
    assert "good.elf" not in out  # stop-on-first rule


def test_absent_manifest_refuses_everything(tmp_path):
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, {}, {"x.elf": ELF_FORGERY_FOR_TESTS}))
    assert not a.ok


def test_non_aarch64_elf_rejected(tmp_path):
    m = {"x.elf": {"kind": "upstream", "sha256": "0" * 64}}
    blob = make_elf(machine=62)  # EM_X86_64
    from hashlib import sha256
    m["x.elf"]["sha256"] = sha256(blob).hexdigest()
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": blob}))
    assert not a.ok and a.reason == "not_aarch64"


def test_32bit_elf_rejected(tmp_path):
    m = {"x.elf": {"kind": "upstream"}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": make_elf(klass=1)}),
                                 allow_placeholder=True)
    assert not a.ok and a.reason == "elf_not_64bit"


def test_big_endian_elf_rejected(tmp_path):
    m = {"x.elf": {"kind": "upstream"}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": make_elf(endian=2)}),
                                 allow_placeholder=True)
    assert not a.ok and a.reason == "elf_not_little_endian"


def test_relocatable_object_rejected(tmp_path):
    m = {"x.elf": {"kind": "upstream"}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": make_elf(e_type=1)}),
                                 allow_placeholder=True)
    assert not a.ok and a.reason == "elf_bad_type"


def test_truncated_elf_rejected(tmp_path):
    import hashlib
    tiny = make_elf()[:32]  # below the 64-byte ELF header minimum
    m = {"x.elf": {"kind": "upstream", "sha256": hashlib.sha256(tiny).hexdigest()}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": tiny}),
                                 allow_placeholder=True, min_bytes=1)
    assert not a.ok and a.reason == "elf_truncated"


def test_shared_object_et_dyn_accepted(tmp_path):
    import hashlib
    blob = make_elf(e_type=3)
    m = {"x.elf": {"kind": "upstream", "sha256": hashlib.sha256(blob).hexdigest()}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": blob}))
    assert a.ok


def test_upstream_without_sha256_is_incomplete(tmp_path):
    m = {"x.elf": {"kind": "upstream", "source_url": "https://x"}}
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": ELF_FORGERY_FOR_TESTS}))
    assert not a.ok and a.reason == "provenance_incomplete_missing_sha256"


def test_malformed_manifest_sha256_rejected(tmp_path):
    for bad in ("zz" * 32, "00" * 31, 12345, "0" * 63):
        m = {"x.elf": {"kind": "upstream", "sha256": bad}}
        a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": ELF_FORGERY_FOR_TESTS}))
        assert not a.ok, bad
        assert a.reason in ("sha256_malformed_in_manifest",
                            "sha256_mismatch_vs_manifest"), (bad, a.reason)


def test_malformed_expected_sha256_rejected(tmp_path):
    import json as _json
    m = {"x.elf": {"kind": "upstream", "sha256": "0" * 64}}
    _json.dump(m, open(tmp_path / pay_mod.MANIFEST_NAME, "w"))
    (tmp_path / "x.elf").write_bytes(ELF_FORGERY_FOR_TESTS)
    a = pay_mod.validate_payload("x.elf", str(tmp_path), expected_sha256="not-hex!!")
    assert not a.ok and a.reason == "sha256_malformed"


def test_modified_file_rejected_against_manifest(tmp_path):
    import hashlib, json as _json
    original = ELF_FORGERY_FOR_TESTS
    m = {"x.elf": {"kind": "upstream", "sha256": hashlib.sha256(original).hexdigest()}}
    tampered = original + b"\x00tampered"
    a = pay_mod.validate_payload("x.elf", _dir(tmp_path, m, files={"x.elf": tampered}))
    assert not a.ok and a.reason == "sha256_mismatch_vs_manifest"
