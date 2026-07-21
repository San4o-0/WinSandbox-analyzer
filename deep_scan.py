import math
import os
import re
import struct
import subprocess
import sys
import zipfile

import config

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".nsp0": "NsPack", ".nsp1": "NsPack",
    "petite": "Petite", ".petite": "Petite",
    "mpress1": "MPRESS", "mpress2": "MPRESS",
    ".themida": "Themida", ".winlice": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".boom": "Boomerang", ".mackt": "ImpREC",
}

RISKY_IMPORTS = {
    "wininet.dll": "network",
    "winhttp.dll": "network",
    "ws2_32.dll": "network",
    "urlmon.dll": "network",
    "crypt32.dll": "crypto",
    "bcrypt.dll": "crypto",
    "advapi32.dll": "system",
    "psapi.dll": "process",
    "shell32.dll": "shell",
    "ntdll.dll": "lowlevel",
}

MACRO_MARKERS = ("vbaproject.bin", "vbadata.xml", "macros/")


def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    result = 0.0
    for count in counts:
        if count:
            p = count / total
            result -= p * math.log2(p)
    return round(result, 2)


def _rva_to_offset(rva, sections):
    for section in sections:
        start = section["vaddr"]
        end = start + max(section["vsize"], section["rawsize"])
        if start <= rva < end:
            return section["raw_ptr"] + (rva - start)
    return None


def _read_cstring(data, offset, limit=64):
    end = data.find(b"\x00", offset, offset + limit)
    if end == -1:
        return ""
    return data[offset:end].decode("ascii", errors="ignore")


def parse_pe(path):
    result = {
        "is_pe": False, "sections": [], "packer": "", "imports": [],
        "has_cert": False, "cert_size": 0, "is_dotnet": False,
        "subsystem": 0, "compiled": 0,
    }
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(0x400)
            if not head.startswith(b"MZ"):
                return result
            pe_off = struct.unpack_from("<I", head, 0x3C)[0]
            if pe_off <= 0 or pe_off > size - 24:
                return result
            f.seek(pe_off)
            coff = f.read(24)
            if not coff.startswith(b"PE\x00\x00"):
                return result
            result["is_pe"] = True
            num_sections, timestamp = struct.unpack_from("<HI", coff, 6)
            opt_size = struct.unpack_from("<H", coff, 20)[0]
            result["compiled"] = timestamp

            opt = f.read(opt_size)
            if len(opt) < 4:
                return result
            magic = struct.unpack_from("<H", opt, 0)[0]
            plus = magic == 0x20B
            dir_base = 112 if plus else 96
            if len(opt) >= (70 if plus else 70):
                result["subsystem"] = struct.unpack_from(
                    "<H", opt, 68 if plus else 68
                )[0]

            directories = []
            offset = dir_base
            while offset + 8 <= len(opt) and len(directories) < 16:
                directories.append(struct.unpack_from("<II", opt, offset))
                offset += 8

            if len(directories) > 4 and directories[4][1]:
                result["has_cert"] = True
                result["cert_size"] = directories[4][1]
            if len(directories) > 14 and directories[14][1]:
                result["is_dotnet"] = True

            f.seek(pe_off + 24 + opt_size)
            raw_sections = f.read(40 * min(num_sections, 96))
            sections = []
            for index in range(len(raw_sections) // 40):
                chunk = raw_sections[index * 40:(index + 1) * 40]
                name = chunk[:8].rstrip(b"\x00").decode("ascii", errors="ignore")
                vsize, vaddr, rawsize, raw_ptr = struct.unpack_from("<IIII", chunk, 8)
                sections.append({
                    "name": name, "vsize": vsize, "vaddr": vaddr,
                    "rawsize": rawsize, "raw_ptr": raw_ptr, "entropy": 0.0,
                })

            for section in sections:
                if 0 < section["rawsize"] and section["raw_ptr"] < size:
                    f.seek(section["raw_ptr"])
                    section["entropy"] = _entropy(f.read(min(section["rawsize"], 1 << 20)))
                key = section["name"].lower()
                if key in PACKER_SECTIONS:
                    result["packer"] = PACKER_SECTIONS[key]
            result["sections"] = sections

            if len(directories) > 1 and directories[1][0]:
                imports = _read_imports(f, directories[1][0], sections, size)
                result["imports"] = imports
    except (OSError, struct.error, ValueError):
        return result
    return result


def _read_imports(f, rva, sections, size):
    table_offset = _rva_to_offset(rva, sections)
    if table_offset is None or table_offset >= size:
        return []
    f.seek(table_offset)
    blob = f.read(20 * 200)
    names = []
    for index in range(len(blob) // 20):
        entry = blob[index * 20:(index + 1) * 20]
        if entry == b"\x00" * 20:
            break
        name_rva = struct.unpack_from("<I", entry, 12)[0]
        if not name_rva:
            continue
        name_offset = _rva_to_offset(name_rva, sections)
        if name_offset is None or name_offset >= size:
            continue
        f.seek(name_offset)
        name = _read_cstring(f.read(64), 0)
        if name:
            names.append(name.lower())
    return names


def read_signer(path, cert_size):
    if not cert_size:
        return ""
    try:
        with open(path, "rb") as f:
            f.seek(max(os.path.getsize(path) - cert_size, 0))
            blob = f.read(min(cert_size, 1 << 20))
    except OSError:
        return ""
    names = []
    for match in re.finditer(b"\x06\x03\x55\x04\x03", blob):
        pos = match.end()
        if pos + 2 > len(blob):
            continue
        tag, length = blob[pos], blob[pos + 1]
        if tag not in (0x0C, 0x13, 0x16) or length > 64:
            continue
        value = blob[pos + 2:pos + 2 + length]
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text.isprintable() and len(text) > 2:
            names.append(text)
    for name in names:
        low = name.lower()
        if not any(word in low for word in ("root", "verisign", "digicert", "sectigo",
                                            "globalsign", "certification", "authority",
                                            "trusted", "thawte", "entrust", "ca ")):
            return name
    return names[0] if names else ""


def verify_signature(path):
    if not sys.platform.startswith("win"):
        return ""
    script = (
        "(Get-AuthenticodeSignature -LiteralPath "
        + '"' + path.replace('"', '`"') + '"'
        + ").Status"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def inspect_container(path, detected_type):
    result = {"is_archive": False, "nested_executables": [], "has_macros": False,
              "entries": 0, "encrypted": False}
    if not zipfile.is_zipfile(path):
        return result
    result["is_archive"] = True
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()[:2000]
            result["entries"] = len(names)
            for info in archive.infolist()[:2000]:
                if info.flag_bits & 0x1:
                    result["encrypted"] = True
                    break
    except (zipfile.BadZipFile, OSError):
        return result
    for name in names:
        low = name.lower()
        if any(marker in low for marker in MACRO_MARKERS):
            result["has_macros"] = True
        extension = os.path.splitext(low)[1]
        if extension in config.EXECUTABLE_EXTENSIONS:
            result["nested_executables"].append(os.path.basename(name) or name)
    result["nested_executables"] = result["nested_executables"][:12]
    return result


def analyze(path, detected_type):
    pe = parse_pe(path)
    container = inspect_container(path, detected_type)
    signer = read_signer(path, pe["cert_size"]) if pe["has_cert"] else ""
    status = verify_signature(path) if pe["has_cert"] else ""

    packed_sections = [
        s["name"] for s in pe["sections"]
        if s["entropy"] >= 7.5 and s["rawsize"] > 4096
    ]
    import_groups = sorted({
        RISKY_IMPORTS[name] for name in pe["imports"] if name in RISKY_IMPORTS
    })

    return {
        "is_pe": pe["is_pe"],
        "is_dotnet": pe["is_dotnet"],
        "section_count": len(pe["sections"]),
        "packer": pe["packer"],
        "packed_sections": packed_sections[:6],
        "import_count": len(pe["imports"]),
        "import_groups": import_groups,
        "few_imports": pe["is_pe"] and 0 < len(pe["imports"]) <= 3,
        "signed": pe["has_cert"],
        "signer": signer,
        "signature_status": status,
        "signature_valid": status == "Valid",
        "signature_broken": status not in ("", "Valid", "UnknownError"),
        "archive": container,
    }
