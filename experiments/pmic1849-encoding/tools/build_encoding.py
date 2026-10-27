"""Hash-pinned stock-derived ARM64 PMIC patch; no deployment operations.

Exactly four existing MUL W8,W8,W9 instructions become direct BLs to
EWDK-assembled arithmetic leaves. Original frames/unwind/WDF code unchanged.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

for deps in [Path(__file__).resolve().parents[2] / 'offline-deps',
             Path(r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')]:
    if deps.exists():
        sys.path.insert(0, str(deps))
        break
import pefile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

STOCK = '533c3a555e111d4b12b657d026c92d63d5170d57297432d03bdaf3be96c7886a'
HOOKS = {0x1CC8: 'EncodeFCC', 0x1CE8: 'EncodeFV',
         0x1D08: 'EncodeUSB', 0x1D28: 'EncodeDC'}
sha = lambda data: hashlib.sha256(data).hexdigest()
align = lambda value, size: (value + size - 1) // size * size


def build(stock_path, obj_path, out_path):
    original = Path(stock_path).read_bytes()
    if sha(original) != STOCK:
        raise ValueError('Unrecognized stock SYS; never apply offsets to another version')
    pe = pefile.PE(data=original)
    assert pe.FILE_HEADER.Machine == 0xAA64
    obj = Path(obj_path).read_bytes()
    machine, count, _, symoff, symcount, optional, _ = struct.unpack_from('<HHIIIHH', obj)
    assert machine == 0xAA64 and optional == 0
    strings = obj[symoff + symcount * 18:]

    def name(raw):
        if raw[:4] == b'\0' * 4:
            offset = struct.unpack_from('<I', raw, 4)[0]
            return strings[offset:].split(b'\0', 1)[0].decode()
        return raw.rstrip(b'\0').decode()

    sections = []
    for i in range(count):
        nm, _, _, size, raw, _, _, relocs, _, flags = struct.unpack_from('<8sIIIIIIHHI', obj, 20 + i * 40)
        assert relocs == 0, 'Arithmetic leaves must be position independent and relocation free'
        sections.append((name(nm), obj[raw:raw + size], flags))
    assert all(not data or nm in {'.text', '.debug$S'} for nm, data, flags in sections)
    allocated = [(nm, data, flags) for nm, data, flags in sections if data and nm == '.text']
    assert len(allocated) == 1
    code = allocated[0][1]
    text_index = next(i + 1 for i, s in enumerate(sections) if s[0] == '.text')
    symbols = {}
    i = 0
    while i < symcount:
        nm, value, section, _, _, aux = struct.unpack_from('<8sIhHBB', obj, symoff + 18 * i)
        if section == text_index:
            symbols[name(nm)] = value
        i += 1 + aux
    helpers = []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    new_rva = align(pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)
    for symbol in HOOKS.values():
        start, end = symbols[symbol], symbols[symbol + 'End']
        instructions = list(md.disasm(code[start:end], new_rva + start))
        assert len(instructions) * 4 == end - start
        assert instructions[-1].mnemonic == 'ret'
        for ins in instructions[:-1]:
            assert ins.mnemonic in {'mov', 'cmp', 'csel', 'sub', 'udiv'}, (symbol, ins.mnemonic)
            assert all(token not in ins.op_str for token in ['sp', 'x18', '[', ']'])
        helpers.append({'name': symbol, 'startRVA': new_rva + start,
                        'endRVA': new_rva + end, 'instructions': len(instructions)})
    assert sum(h['endRVA'] - h['startRVA'] for h in helpers) == len(code)
    raw_end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
    result = bytearray(original[:raw_end])  # discard invalidated original certificate overlay
    changes = []
    for site, symbol in HOOKS.items():
        old = pe.get_data(site, 4)
        ins = list(md.disasm(old, site))
        assert len(ins) == 1 and ins[0].mnemonic == 'mul' and ins[0].op_str == 'w8, w8, w9'
        target = new_rva + symbols[symbol]
        delta = target - site
        assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27)
        word = 0x94000000 | ((delta // 4) & 0x3FFFFFF)
        struct.pack_into('<I', result, pe.get_offset_from_rva(site), word)
        changes.append({'siteRVA': site, 'symbol': symbol, 'targetRVA': target,
                        'oldHex': old.hex(), 'newHex': struct.pack('<I', word).hex()})
    new_header = pe.sections[0].get_file_offset() + 40 * len(pe.sections)
    assert new_header + 40 <= pe.OPTIONAL_HEADER.SizeOfHeaders
    assert result[new_header:new_header + 40] == b'\0' * 40
    pointer = align(len(result), 0x200)
    result.extend(b'\0' * (pointer - len(result)))
    raw_size = align(len(code), 0x200)
    result.extend(code + b'\0' * (raw_size - len(code)))
    header = struct.pack('<8sIIIIIIHHI', b'.nenc\0\0\0', len(code), new_rva,
                         raw_size, pointer, 0, 0, 0, 0, 0x60000020)
    result[new_header:new_header + 40] = header
    struct.pack_into('<H', result, pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'), len(pe.sections) + 1)

    def opt(field, value):
        struct.pack_into('<I', result, pe.OPTIONAL_HEADER.get_field_absolute_offset(field), value)

    opt('SizeOfImage', align(new_rva + len(code), 0x1000))
    opt('SizeOfCode', pe.OPTIONAL_HEADER.SizeOfCode + raw_size)
    struct.pack_into('<II', result, pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(), 0, 0)
    opt('CheckSum', 0)
    opt('CheckSum', pefile.PE(data=bytes(result)).generate_checksum())
    built = pefile.PE(data=bytes(result))
    assert built.verify_checksum()
    assert built.OPTIONAL_HEADER.AddressOfEntryPoint == pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for index in range(16):
        if index == 4:
            continue
        old, new = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index], built.OPTIONAL_HEADER.DATA_DIRECTORY[index]
        assert (old.VirtualAddress, old.Size) == (new.VirtualAddress, new.Size)
        assert pe.get_data(old.VirtualAddress, old.Size) == built.get_data(new.VirtualAddress, new.Size)
    observed = []
    for section in pe.sections:
        before = section.get_data()
        after = built.get_data(section.VirtualAddress, len(before))
        changed = [section.VirtualAddress + i for i in range(0, len(before), 4) if before[i:i + 4] != after[i:i + 4]]
        observed.extend(changed)
    assert observed == list(HOOKS), observed
    assert all(not(s.Characteristics & 0x80000000 and s.Characteristics & 0x20000000) for s in built.sections)
    output = Path(out_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(result)
    report = {'schema': 1, 'name': 'pmic1849-encoding', 'status': 'OFFLINE_CANDIDATE',
              'inputStockSHA256': STOCK, 'objectSHA256': sha(obj), 'unsignedSHA256': sha(result),
              'helpers': helpers, 'hooks': changes, 'newSection': '.nenc',
              'originalSectionsOnlyFourInstructionsChanged': True,
              'entryPointAndAllNonSecurityDirectoriesUnchanged': True,
              'newImports': False, 'newStackFrames': False, 'newHardwareRegisters': False,
              'roleOrSuspendPolicyChanged': False, 'installed': False,
              'completeChargingFix': False, 'bootTested': False}
    output.with_suffix('.build.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--stock', required=True)
    ap.add_argument('--object', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    build(args.stock, args.object, args.output)
