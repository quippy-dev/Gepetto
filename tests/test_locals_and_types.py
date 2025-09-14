import pytest

try:
    import idaapi  # type: ignore
    HAVE_IDA = True
except Exception:
    HAVE_IDA = False


@pytest.mark.skipif(not HAVE_IDA, reason="IDA not available")
def test_parse_type_declaration_roundtrip():
    # Basic sanity of the helper; if IDA is present we can parse core types
    from gepetto.ida.utils.ida9_utils import parse_type_declaration
    tif = parse_type_declaration("int *")
    assert hasattr(tif, "is_ptr")
    assert tif.is_ptr()

    tif2 = parse_type_declaration("char[32]")
    # Not asserting specific attributes; just ensure an object is returned
    assert str(tif2)


@pytest.mark.skipif(not HAVE_IDA, reason="IDA not available")
def test_locals_graceful_when_hexrays_unavailable(monkeypatch):
    # Ensure locals tools produce clear error when Hex-Rays isn't available
    import gepetto.ida.tools.locals_and_types as lat

    # Force hexrays_available() to False at the module under test
    monkeypatch.setattr(lat, "hexrays_available", lambda: False)

    # Provide an arbitrary EA string; parse_ea will run but the main logic should short-circuit on hexrays
    res1 = lat.rename_local_variable("0x401000", "old", "new")
    assert res1.get("ok") is False
    assert "Hex-Rays not available" in (res1.get("error") or "")

    res2 = lat.set_local_variable_type("0x401000", "v", "int")
    assert res2.get("ok") is False
    assert "Hex-Rays not available" in (res2.get("error") or "")