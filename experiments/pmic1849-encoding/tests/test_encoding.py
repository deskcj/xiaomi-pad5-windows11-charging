"""Execute candidate ARM64 instructions only in Unicorn with simulated WDF.

No kernel driver load, PMIC access, IOCTL to Windows or live registry changes.
Reference is extracted pinned Android units/steps, independent of assembly.
"""
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for deps in [ROOT.parent / 'offline-deps', Path(r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')]:
    if deps.exists():
        sys.path.insert(0, str(deps))
        break
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'build/qcpmicext8150_unsigned.sys'
pe = pefile.PE(str(path))
metadata = json.loads((ROOT / 'build/qcpmicext8150_unsigned.build.json').read_text())
spec_path = ROOT / 'reference/REGISTER-ENCODING-SPEC.json'
spec = json.loads(spec_path.read_text())
profiles = {row['name']: row for row in spec['parameters']}
caps = {'fcc': spec['boardSourceLimits']['fcc-max-ua'],
        'fv': spec['boardSourceLimits']['fv-max-uv'],
        'usb_icl': spec['boardSourceLimits']['usb-icl-ua'],
        'dc_icl': profiles['dc_icl']['max_u']}
NAMES = ['fcc', 'fv', 'usb_icl', 'dc_icl']
REGS = [0x1061, 0x1070, 0x1370, 0x118C]
assert [profiles[n]['step_u'] for n in NAMES] == [50000, 10000, 50000, 40000]
assert [caps[n] for n in NAMES] == [5900000, 4470000, 3000000, 1200000]


def reference(name, milli):
    p = profiles[name]
    micro = (milli & 0xFFFFFFFF) * 1000
    bounded = max(p['min_u'], min(micro, p['max_u'], caps[name]))
    return (bounded - p['min_u']) // p['step_u']


BASE = pe.OPTIONAL_HEADER.ImageBase
STACK = 0x200000
STOP = 0x400000
FAKE = 0x500000
DATA = 0x600000
CONTEXT = DATA + 0x1000
INPUT = DATA + 0x2000
OUTPUT = DATA + 0x3000
IMAGE = pe.get_memory_mapped_image()
XREGS = [UC_ARM64_REG_X0 + i for i in range(29)] + [UC_ARM64_REG_FP, UC_ARM64_REG_LR]
NVS = {XREGS[i]: 0xABC0000000000000 + i - 19 for i in range(19, 29)}
NVS[UC_ARM64_REG_FP] = 0xABC1234567890000

leaf_cases = 0
for name, helper in zip(NAMES, metadata['helpers']):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(BASE, 0x20000)
    uc.mem_write(BASE, IMAGE)
    uc.mem_map(STACK, 0x10000)
    uc.mem_map(STOP, 0x1000)
    for i, reg in enumerate(XREGS):
        uc.reg_write(reg, 0xABC0000000000000 + i)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x8000)
    uc.reg_write(UC_ARM64_REG_LR, STOP)
    expected_regs = {reg: uc.reg_read(reg) for i, reg in enumerate(XREGS) if i not in [8, 9]}
    memory_accesses = []
    uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, lambda *args: memory_accesses.append(args[2]))
    rnd = random.Random(0x1849)
    values = list(range(65536)) + [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF] + [rnd.getrandbits(32) for _ in range(1000)]
    previous = -1
    for value in values:
        uc.reg_write(UC_ARM64_REG_W8, value)
        uc.emu_start(BASE + helper['startRVA'], STOP, count=20)
        actual = uc.reg_read(UC_ARM64_REG_W8)
        assert uc.reg_read(UC_ARM64_REG_PC) == STOP
        assert actual == reference(name, value), (name, value, actual)
        if value < 65536:
            assert actual >= previous
            previous = actual
        leaf_cases += 1
    assert not memory_accesses, 'Arithmetic helper accessed memory'
    assert uc.reg_read(UC_ARM64_REG_SP) == STACK + 0x8000
    assert all(uc.reg_read(reg) == value for reg, value in expected_regs.items())

snapshots = {}
full_cases = 0


def run(values=(4500, 4450, 1500, 1000), *, null_input=False, null_output=False,
        missing_target=False, faults=None, logging=False, load_base=BASE,
        capture=False, dispatcher=False, clobber=0xA5A5A5A5A5A5A5A5):
    global full_cases
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(load_base, 0x20000)
    uc.mem_write(load_base, IMAGE)
    uc.mem_map(STACK, 0x10000)
    uc.mem_write(STACK, b'\xD3' * 0x10000)
    uc.mem_map(STOP, 0x1000)
    uc.mem_map(FAKE, 0x1000)
    uc.mem_map(DATA, 0x10000)
    table = DATA + 0x4000
    uc.mem_write(load_base + 0xD488, struct.pack('<Q', table))
    uc.mem_write(load_base + 0xD490, struct.pack('<Q', DATA + 0x5000))
    for off, target in [(0x9C8, FAKE + 0x10), (0x9D0, FAKE + 0x20), (0x5D0, FAKE + 0x30)]:
        uc.mem_write(table + off, struct.pack('<Q', target))
    uc.mem_write(load_base + 0xC0A8, struct.pack('<Q', FAKE))
    uc.mem_write(load_base + 0xD098, struct.pack('<Q', load_base + 0xD098 if not logging else DATA + 0x6000))
    uc.mem_write(load_base + 0xD090, struct.pack('<Q', DATA + 0x6000))
    uc.mem_write(DATA + 0x6048, b'\x01\0')
    uc.mem_write(CONTEXT + 0xE8 + 8, struct.pack('<Q', 0 if missing_target else DATA + 0x7000))
    uc.mem_write(CONTEXT + 0xE8 + 0x18, struct.pack('<Q', DATA + 0x8000))
    uc.mem_write(INPUT, struct.pack('<5I', 1, *values))
    uc.mem_write(OUTPUT, b'\xCC' * 16)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x8000)
    uc.reg_write(UC_ARM64_REG_LR, STOP)
    for reg, value in NVS.items():
        uc.reg_write(reg, value)
    uc.reg_write(UC_ARM64_REG_X18, 0x1818181818181818)
    uc.reg_write(UC_ARM64_REG_X0, CONTEXT)
    if dispatcher:
        uc.reg_write(UC_ARM64_REG_W1, 0x801B0FA0)
        uc.reg_write(UC_ARM64_REG_X2, 0 if null_input else INPUT)
        uc.reg_write(UC_ARM64_REG_X3, 20)
        uc.reg_write(UC_ARM64_REG_X4, 0 if null_output else OUTPUT)
        uc.reg_write(UC_ARM64_REG_X5, 4)
        uc.reg_write(UC_ARM64_REG_X6, OUTPUT + 8)
    else:
        uc.reg_write(UC_ARM64_REG_X1, 0 if null_input else INPUT)
        uc.reg_write(UC_ARM64_REG_X2, 20)
        uc.reg_write(UC_ARM64_REG_X3, 0 if null_output else OUTPUT)
    writes = []
    locks = []
    trace_calls = []
    faults = faults or {}
    depth = 0

    def ret(result=0, preserve=False):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        if not preserve:
            for reg in XREGS[:18]:
                uc.reg_write(reg, clobber)
            uc.reg_write(UC_ARM64_REG_W0, result)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def hook(cpu, address, size, user):
        nonlocal depth
        rva = address - load_base
        if capture and (0x1C28 <= rva < 0x1D98 or 0x5C78 <= rva < 0x5E08 or 0x4AC8 <= rva < 0x4BF0 or 0x14000 <= rva < 0x14070):
            regs = [cpu.reg_read(r) for r in XREGS]
            sp = cpu.reg_read(UC_ARM64_REG_SP) - (STACK + 0x7000)
            memory = bytes(cpu.mem_read(STACK + 0x7000, 0x2000))
            # Keep every distinct instruction boundary/state, across error paths.
            key = (rva, sp, tuple(regs))
            snapshots[key] = (rva, sp, regs, memory)
        if 0x14000 <= rva < 0x14070:
            assert cpu.reg_read(UC_ARM64_REG_SP) % 16 == 0
        if address == FAKE:
            ret(preserve=True)  # simulate only CFG validation, no argument mutation
        elif address in [FAKE + 0x10, FAKE + 0x20]:
            acquire = address == FAKE + 0x10
            depth += 1 if acquire else -1
            assert depth in [0, 1], 'Unbalanced/nonserialized lock calls'
            locks.append(acquire)
            ret()
        elif address == FAKE + 0x30:
            assert depth == 1
            assert cpu.reg_read(UC_ARM64_REG_W3) == 0x802B0FA0
            assert cpu.reg_read(UC_ARM64_REG_X1) == DATA + 0x7000
            in_desc = bytes(cpu.mem_read(cpu.reg_read(UC_ARM64_REG_X4), 24))
            out_desc = bytes(cpu.mem_read(cpu.reg_read(UC_ARM64_REG_X5), 24))
            assert struct.unpack_from('<I', in_desc)[0] == struct.unpack_from('<I', out_desc)[0] == 1
            in_ptr, in_len = struct.unpack_from('<QQ', in_desc, 8)
            out_ptr, out_len = struct.unpack_from('<QQ', out_desc, 8)
            assert in_len == 12 and out_len == 4
            sid, reg, raw = struct.unpack('<III', bytes(cpu.mem_read(in_ptr, 12)))
            assert sid == 2 and reg == REGS[len(writes)]
            writes.append([sid, reg, raw])
            status, vendor, length = faults.get(len(writes) - 1, (0, 0, 4))
            cpu.mem_write(out_ptr, struct.pack('<I', vendor))
            cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X7), struct.pack('<Q', length))
            ret(status)
        elif rva in [0x1510, 0x1930, 0x55A8, 0x15F8]:
            trace_calls.append(rva)
            ret()

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(load_base + (0x2800 if dispatcher else 0x1C28), STOP, count=10000)
    assert uc.reg_read(UC_ARM64_REG_PC) == STOP
    assert uc.reg_read(UC_ARM64_REG_SP) == STACK + 0x8000
    assert all(uc.reg_read(reg) == value for reg, value in NVS.items())
    assert uc.reg_read(UC_ARM64_REG_X18) == 0x1818181818181818
    assert depth == 0 and len(locks) % 2 == 0
    invalid = null_input or null_output
    if invalid:
        assert not writes and not locks
    else:
        assert locks == [True, False] * 4
        if missing_target:
            assert not writes
        else:
            assert writes == [[2, reg, reference(n, v)] for reg, n, v in zip(REGS, NAMES, values)]
    error = invalid or missing_target or any(s != 0 or v != 0 or n != 4 for s, v, n in faults.values())
    assert uc.reg_read(UC_ARM64_REG_W0) == (0xC0000001 if error else 0)
    if not invalid:
        assert struct.unpack('<I', bytes(uc.mem_read(OUTPUT, 4)))[0] == (0x6D if error else 0)
    assert logging == bool(trace_calls)
    full_cases += 1


boundaries = [0, 1, 9, 10, 39, 40, 49, 50, 51, 100, 499, 500, 900,
              1199, 1200, 1201, 1499, 1500, 1501, 2999, 3000, 3001,
              3487, 3599, 3600, 3601, 4449, 4450, 4469, 4470, 4471,
              4500, 4790, 4800, 4919, 5900, 65535, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
for field in range(4):
    for value in boundaries:
        values = [4500, 4450, 1500, 1000]
        values[field] = value
        run(values)
for logging in [False, True]:
    for dispatcher in [False, True]:
        for null_input, null_output in [(False, False), (True, False), (False, True), (True, True)]:
            run(null_input=null_input, null_output=null_output, logging=logging, dispatcher=dispatcher)
    run(missing_target=True, logging=logging)
    for fail_at in range(4):
        for fault in [(0xC0000001, 0, 4), (0x102, 0, 4), (0x40000000, 0, 4), (0, 1, 4),
                      (0, 0x6D, 4), (0, 0, 0), (0, 0, 3), (0, 0, 8)]:
            run(faults={fail_at: fault}, logging=logging)
for load_base in [0x10000000, 0x180000000, 0x7FFB12340000]:
    for clobber in [0, 0xFFFFFFFFFFFFFFFF, 0xA5A5A5A5A5A5A5A5]:
        run(load_base=load_base, clobber=clobber)
for kwargs in [{}, {'logging': True}, {'null_input': True}, {'null_output': True},
               {'missing_target': True}, {'faults': {0: (0xC0000001, 0, 4)}},
               {'logging': True, 'faults': {1: (0, 0x6D, 4)}},
               {'faults': {3: (0, 0, 3)}}]:
    run(capture=True, **kwargs)

fixtures = ROOT / 'build/unwind-fixtures.bin'
with fixtures.open('wb') as stream:
    stream.write(struct.pack('<II', 0x3157444E, len(snapshots)))
    for pc, sp, regs, memory in snapshots.values():
        stream.write(struct.pack('<II31Q', pc, sp, *regs) + memory)
report = {'candidate': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
          'encodingSpecSHA256': hashlib.sha256(spec_path.read_bytes()).hexdigest(),
          'passedArithmeticARM64Cases': leaf_cases, 'passedFullSetterARM64Cases': full_cases,
          'allUnsigned16BitInputsPerField': True, 'random32BitCasesPerField': 1000,
          'nativeUnwindFixtures': len(snapshots), 'additionalASLRBases': 3,
          'simulatedTransportIsActual4AC8WdfCall': True, 'actual5C78ReplyValidationExercised': True,
          'nullPointersAndTransportVendorLengthErrors': True, 'preservedNonvolatileAndX18': True,
          'helperMemoryAccesses': 0, 'hardwareIOPerformed': False, 'kernelDriverLoaded': False,
          'bootTested': False, 'hotplugFixed': False}
(ROOT / 'build/emulation-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
with (ROOT / 'build/candidate-disasm.txt').open('w', encoding='utf-8') as f:
    for helper in metadata['helpers']:
        for ins in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(pe.get_data(helper['startRVA'], helper['endRVA'] - helper['startRVA']), helper['startRVA']):
            f.write(f'{ins.address:x} {ins.mnemonic} {ins.op_str}\n')
print(json.dumps(report, indent=2))
