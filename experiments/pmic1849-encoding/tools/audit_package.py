"""Verify exactly what changed and bind signed package to offline QA."""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for deps in [ROOT.parent / 'offline-deps', Path(r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')]:
    if deps.exists():
        sys.path.insert(0, str(deps))
        break
import pefile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

sha = lambda b: hashlib.sha256(b).hexdigest()
stock_path = Path(r'C:\Windows\System32\DriverStore\FileRepository\qcpmicext8150.inf_arm64_fe1800db720f064c\qcpmicext8150.sys')
unsigned_path = ROOT / 'build/qcpmicext8150_unsigned.sys'
signed_path = ROOT / 'package/qcpmicext8150.sys'
stock, unsigned, signed = [pefile.PE(str(p)) for p in [stock_path, unsigned_path, signed_path]]
assert sha(stock_path.read_bytes()) == '533c3a555e111d4b12b657d026c92d63d5170d57297432d03bdaf3be96c7886a'
assert unsigned.verify_checksum() and signed.verify_checksum()
assert unsigned.FILE_HEADER.Machine == signed.FILE_HEADER.Machine == 0xAA64
assert len(unsigned.sections) == len(signed.sections) == len(stock.sections) + 1
for left, right in zip(unsigned.sections, signed.sections):
    assert (left.Name, left.VirtualAddress, left.Misc_VirtualSize, left.Characteristics) == (right.Name, right.VirtualAddress, right.Misc_VirtualSize, right.Characteristics)
    assert left.get_data() == right.get_data(), 'Signing modified a mapped section'
for index in range(16):
    if index == 4:
        continue
    a, b = unsigned.OPTIONAL_HEADER.DATA_DIRECTORY[index], signed.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    assert (a.VirtualAddress, a.Size) == (b.VirtualAddress, b.Size)
    assert unsigned.get_data(a.VirtualAddress, a.Size) == signed.get_data(b.VirtualAddress, b.Size)
    c = stock.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    assert (a.VirtualAddress, a.Size) == (c.VirtualAddress, c.Size)
    assert unsigned.get_data(a.VirtualAddress, a.Size) == stock.get_data(c.VirtualAddress, c.Size)
assert not any(s.Characteristics & 0x80000000 and s.Characteristics & 0x20000000 for s in signed.sections)
assert unsigned.OPTIONAL_HEADER.AddressOfEntryPoint == stock.OPTIONAL_HEADER.AddressOfEntryPoint
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
changes = []
for section in stock.sections:
    old = section.get_data()
    new = signed.get_data(section.VirtualAddress, len(old))
    for offset in range(0, len(old), 4):
        if old[offset:offset + 4] != new[offset:offset + 4]:
            rva = section.VirtualAddress + offset
            a = next(md.disasm(old[offset:offset + 4], rva))
            b = next(md.disasm(new[offset:offset + 4], rva))
            changes.append({'rva': hex(rva), 'stock': f'{a.mnemonic} {a.op_str}', 'candidate': f'{b.mnemonic} {b.op_str}'})
assert [int(c['rva'], 16) for c in changes] == [0x1CC8, 0x1CE8, 0x1D08, 0x1D28]
assert all(c['stock'] == 'mul w8, w8, w9' and c['candidate'].startswith('bl ') for c in changes)
manifest = json.loads((ROOT / 'package-manifest.json').read_text(encoding='utf-8-sig'))
for file in manifest['files']:
    data = (ROOT / file['path']).read_bytes()
    assert sha(data).upper() == file['sha256'].upper()
    assert len(data) == file['bytes']
qa = json.loads((ROOT / 'build/emulation-report.json').read_text())
assert qa['sha256'] == sha(unsigned_path.read_bytes())
assert (ROOT / 'build/qcpmicext8150_rebuilt.sys').read_bytes() == unsigned_path.read_bytes()
for name in ['native-unwind-report.json', 'native-unwind-signed-report.json']:
    result = json.loads((ROOT / 'build' / name).read_text(encoding='utf-8-sig'))
    assert result['failures'] == 0 and result['nativeARM64UnwindCases'] == qa['nativeUnwindFixtures']
inf = (ROOT / 'package/qcpmicext8150.inf').read_text(encoding='utf-16')
stock_inf = stock_path.with_suffix('.inf').read_text(encoding='utf-16')
import re
normalize_version = lambda t: re.sub(r'DriverVer\s*=\s*[\d/]+,\s*[\d.]+', 'DriverVer = VERSION', t)
assert normalize_version(inf) == normalize_version(stock_inf), 'Unexpected INF changes'
assert '1.0.1849.0' in inf
report = {'unsignedSHA256': sha(unsigned_path.read_bytes()), 'signedSHA256': sha(signed_path.read_bytes()),
          'signedMappedSectionsEqualUnsigned': True, 'rebuildByteIdentical': True,
          'oldSectionsDifferOnlyAt': changes, 'newCodeBytes': signed.sections[-1].Misc_VirtualSize,
          'entryPointImportsLoadConfigUnwindRelocationsPreserved': True,
          'INFOnlyDriverVersionChanged': True, 'RWX': False,
          'kernelLoaded': False, 'bootTested': False, 'fullHotplugFix': False}
(ROOT / 'build/static-image-audit.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, indent=2))
