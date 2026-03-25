import idaapi
import ida_bytes
import ida_name
import ida_struct
import ida_funcs
import ida_kernwin
import idautils
import idc
import json

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

STRUCT_NAME = "CM_CONTROL_VECTOR"
SYMBOL_NAME = "CmControlVector"
MAX_ENTRIES = 1024

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def get_symbol_name(ea):
    name = ida_name.get_ea_name(ea)
    return name if name else None

def read_ptr(ea):
    return ida_bytes.get_qword(ea)

def read_int32(ea):
    val = ida_bytes.get_dword(ea)
    if val != idaapi.BADADDR32:
        return val
    return None

def read_int64(ea):
    val = ida_bytes.get_qword(ea)
    if val != idaapi.BADADDR64:
        return val
    return None

def read_size_t(ea):
    return ida_bytes.get_qword(ea)

def read_utf16_string(ea, max_len=0x1000):
    if ea == 0:
        return None
    data = bytearray()
    for i in range(0, max_len, 2):
        w = ida_bytes.get_word(ea + i)
        if w == 0:
            break
        data += w.to_bytes(2, "little")
    if not data:
        return ""
    try:
        return data.decode("utf-16-le", errors="ignore")
    except Exception:
        return None


def collect_xrefs(target_ea, ignore=None):
    results = []
    for xref in idautils.XrefsTo(target_ea, flags=0):
        src = xref.frm
        if ignore is not None and src == ignore:
            continue
        # Get the function containing the reference, if any
        func = ida_funcs.get_func(src)
        func_name = ida_funcs.get_func_name(func.start_ea) if func else None

        results.append({
            "Function": func_name,
            "Address": src
        })
    return results

# ------------------------------------------------------------
# Struct Definition
# ------------------------------------------------------------

def ensure_struct():
    """
    Ensure CM_CONTROL_VECTOR struct exists with all members.
    Returns: struc_t object
    """
    sid = ida_struct.get_struc_id(STRUCT_NAME)
    if sid == idaapi.BADADDR:
        sid = ida_struct.add_struc(-1, STRUCT_NAME, 0)
        if sid == idaapi.BADADDR:
            raise RuntimeError(f"Failed to create struct '{STRUCT_NAME}'")

    sptr = ida_struct.get_struc(sid)
    if sptr is None:
        raise RuntimeError(f"Failed to get struct '{STRUCT_NAME}'")

    # Ensure all members exist
    members = [
        ("KeyPath", 0x00),
        ("ValueName", 0x08),
        ("pTargetBuffer", 0x10),
        ("sizeOptional", 0x18),
        ("typeOptional", 0x20),
        ("flagsOptional", 0x28)
    ]
    for name, offset in members:
        m = ida_struct.get_member_by_name(sptr, name)
        if m is None:
            ida_struct.add_struc_member(sptr, name, offset, ida_bytes.FF_QWORD, None, 8)

    return sptr

def get_member_offset(sptr, name):
    m = ida_struct.get_member_by_name(sptr, name)
    if not m:
        raise RuntimeError(f"Struct member not found: {name}")
    return m.soff

# ------------------------------------------------------------
# Entry Parsing
# ------------------------------------------------------------

def parse_optional_int(ptr):
    if ptr == 0:
        return None
    value = read_int32(ptr)
    return {
        "Address": ptr,
        "SymbolName": get_symbol_name(ptr),
        "Value": value
    }

def parse_size_optional(ptr, ignore_from=None):
    if ptr == 0:
        return None
    #value = read_size_t(ptr)
    value = read_int32(ptr)
    return {
        "Address": ptr,
        "SymbolName": get_symbol_name(ptr),
        "Value": value,
        "Xrefs": collect_xrefs(ptr, ignore_from)
    }

def parse_target_buffer(ptr, ignore_from=None):
    if ptr == 0:
        return None
    return {
        "Address": ptr,
        "Value": read_int32(ptr),
        "SymbolName": get_symbol_name(ptr),
        "Xrefs": collect_xrefs(ptr, ignore_from)
    }

def parse_entry(base, sptr):
    off_key = get_member_offset(sptr, "KeyPath")
    off_value = get_member_offset(sptr, "ValueName")
    off_target = get_member_offset(sptr, "pTargetBuffer")
    off_size = get_member_offset(sptr, "sizeOptional")
    off_type = get_member_offset(sptr, "typeOptional")
    off_flags = get_member_offset(sptr, "flagsOptional")

    key_ptr = read_ptr(base + off_key)
    if key_ptr == 0:
        return None

    value_ptr = read_ptr(base + off_value)
    target_ptr = read_ptr(base + off_target)
    size_ptr = read_ptr(base + off_size)
    type_ptr = read_ptr(base + off_type)
    flags_val = read_int64(base + off_flags)

    return {
        "KeyPath": read_utf16_string(key_ptr),
        "ValueName": read_utf16_string(value_ptr),
        "pTargetBuffer": parse_target_buffer(target_ptr, base + off_target),
        "sizeOptional": parse_size_optional(size_ptr, base + off_size),
        "typeOptional": parse_optional_int(type_ptr),
        "flagsOptional": flags_val,
    }

# ------------------------------------------------------------
# DumpIt
# ------------------------------------------------------------

def dumpIt(fileName=None):
    sptr = ensure_struct()
    struct_id = sptr.id
    struct_size = ida_struct.get_struc_size(sptr)

    base = ida_name.get_name_ea(idaapi.BADADDR, SYMBOL_NAME)
    if base == idaapi.BADADDR:
        print(f"Symbol {SYMBOL_NAME} not found")
        return

    results = []
    index = 0

    while index < MAX_ENTRIES:
        entry_ea = base + index * struct_size
        ida_bytes.create_struct(entry_ea, struct_size, struct_id)

        entry = parse_entry(entry_ea, sptr)
        if entry is None:
            break

        results.append(entry)
        index += 1

    if not fileName:
        print(json.dumps(results, indent=3))
    else:
        with open(fileName, "w") as f:
            json.dump(results, f, indent=3)

    ida_kernwin.msg(f"\nParsed {len(results)} {STRUCT_NAME} entries\n")
