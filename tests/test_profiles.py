"""Unit tests for firmware profile parsing and matching."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import firmware  # noqa: E402

PROFILES_PATH = os.path.join(os.path.dirname(__file__), "..", "config",
                             "firmware_profiles.json")


def test_parse_fw_variants():
    assert firmware.parse_fw("5.10.0") == 5.10
    assert firmware.parse_fw("14.10.00.00") == 14.10
    assert firmware.parse_fw("08.20.02.00-V0.00") == 8.20
    assert firmware.parse_fw("garbage") is None


def test_profiles_load_nonempty():
    profiles = firmware.load_profiles(PROFILES_PATH)
    assert len(profiles) >= 8


def test_all_spec_seeds_present():
    profiles = firmware.load_profiles(PROFILES_PATH)
    ranges = {p.fw_range for p in profiles}
    for seed in ("1.00-2.70", "3.00-4.51", "4.03-4.51", "5.00-7.61",
                 "8.00-10.01", "10.01-12.70", "7.00-13.60", "14.00-14.10"):
        assert seed in ranges, seed


def test_match_1410_maps_to_experimental_profile():
    profiles = firmware.load_profiles(PROFILES_PATH)
    p = firmware.match_profile(profiles, 14.10)
    assert p is not None
    assert p.id == "unsupported_140x"
    assert p.experimental is True
    assert "UNVERIFIED" in p.notes or p.experimental


def test_match_1360_maps_to_relapse():
    profiles = firmware.load_profiles(PROFILES_PATH)
    p = firmware.match_profile(profiles, 13.60)
    assert p is not None
    assert p.kernel_stage == "relapse_kernel"
    assert p.experimental is False


def test_no_match_below_100():
    profiles = firmware.load_profiles(PROFILES_PATH)
    assert firmware.match_profile(profiles, 0.94) is None
    assert firmware.match_profile(profiles, None) is None


def test_profile_chain_unchanged():
    profiles = firmware.load_profiles(PROFILES_PATH)
    for p in profiles:
        assert p.payload_chain == ["kstuff.elf", "ShadowMountPlus.elf",
                                   "etaHEN.elf", "notify.elf", "ftpsrv.elf"]
