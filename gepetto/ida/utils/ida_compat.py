"""
IDA compatibility utilities for version-specific features.
"""

try:
    import idaapi
except ImportError:
    idaapi = None

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

def get_ida_version() -> tuple[int, int]:
    """
    Returns the IDA version as a tuple (major, minor).
    """
    if not idaapi:
        return (0, 0)

    try:
        version_str = idaapi.get_kernel_version()
        parts = version_str.split('.')
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return (major, minor)
    except Exception:
        return (0, 0)

def is_ida7() -> bool:
    """
    Check if the current IDA version is 7.x.
    """
    major, _ = get_ida_version()
    return major == 7

def is_ida8() -> bool:
    """
    Check if the current IDA version is 8.x.
    """
    major, _ = get_ida_version()
    return major == 8

def is_ida9plus() -> bool:
    """
    Check if the current IDA version is 9.x or newer.
    """
    major, _ = get_ida_version()
    return major >= 9

def has_hexrays() -> bool:
    """
    Check if Hex-Rays decompiler is available and initialized.
    """
    try:
        if not ida_hexrays:
            return False
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False

def has_qt() -> bool:
    """
    Check if Qt bindings are available.
    """
    try:
        from gepetto.qt_compat import QtWidgets
        return QtWidgets is not None
    except ImportError:
        return False

def has_execute_sync() -> bool:
    """
    Check if ida_kernwin.execute_sync is available.
    """
    try:
        import ida_kernwin
        return hasattr(ida_kernwin, 'execute_sync')
    except ImportError:
        return False
