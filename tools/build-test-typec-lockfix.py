"""Offline research candidate only. Never loads, installs, or executes a kernel driver.

Unicorn executes the original/patched ARM64 helpers with mocked WDF/PMIC/WPP calls.
"""
import hashlib
import argparse
import itertools
import json
import struct
import sys
from pathlib import Path
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--research-folder', type=Path, required=True,
                    help='Folder containing a copy of the exact audited qcusbctcpm8150.sys')
parser.add_argument('--python-deps', type=Path, help='Optional isolated pefile/capstone/unicorn directory')
arguments = parser.parse_args()
if arguments.python_deps:
    sys.path.insert(0, str(arguments.python_deps))
import pefile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

folder = arguments.research_folder.resolve()
out = folder / 'typec-lockfix1'
out.mkdir(exist_ok=True)
source = (folder / 'qcusbctcpm8150.sys').read_bytes()
source_hash = hashlib.sha256(source).hexdigest()
assert source_hash == '7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067'
original = pefile.PE(data=source)
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
patched = bytearray(source)
patches = []

def patch_word(rva, expected_text, word):
    offset = original.get_offset_from_rva(rva)
    before = bytes(patched[offset:offset+4])
    instruction = next(cs.disasm(before, rva))
    assert instruction.mnemonic + ' ' + instruction.op_str == expected_text, (hex(rva), instruction.op_str)
    after = struct.pack('<I', word)
    changed = next(cs.disasm(after, rva))
    patches.append({'rva': hex(rva), 'before': before.hex(), 'after': after.hex(),
                    'beforeInstruction': expected_text, 'afterInstruction': changed.mnemonic+' '+changed.op_str})
    patched[offset:offset+4] = after

# Directly reuse the original successful-path unlock instruction; no new code region.
unlock_word = struct.unpack('<I', original.get_data(0x8f14, 4))[0]
assert unlock_word == 0xb9011a9f
for load_rva, unlock_rva, trace_rva, literal in ((0x8f5c, 0x8f60, 0x8f78, 0x8fc4),
                                               (0x90ec, 0x90f0, 0x9108, 0x9154)):
    instruction = struct.unpack('<I', original.get_data(load_rva, 4))[0]
    patch_word(load_rva, f'ldr w10, #0x{literal:x}', (instruction & ~31) | 21)
    patch_word(unlock_rva, 'mov w21, w10', unlock_word)
    patch_word(trace_rva, 'mov w5, w10', 0x2a1503e5)

security = original.OPTIONAL_HEADER.DATA_DIRECTORY[4]
cert_end = security.VirtualAddress + security.Size
if security.VirtualAddress and cert_end == len(patched):
    patched = patched[:security.VirtualAddress]
struct.pack_into('<II', patched, security.get_file_offset(), 0, 0)
check_offset = original.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
struct.pack_into('<I', patched, check_offset, 0)
candidate_pe = pefile.PE(data=bytes(patched))
struct.pack_into('<I', patched, check_offset, candidate_pe.generate_checksum())
candidate_pe = pefile.PE(data=bytes(patched))
candidate = out / 'qcusbctcpm8150-lockfix1-UNSIGNED-NOT-INSTALLED.sys'
candidate.write_bytes(patched)

for directory_index in (1, 3, 5, 10, 12):
    a = original.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
    b = candidate_pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
    assert (a.VirtualAddress, a.Size) == (b.VirtualAddress, b.Size)
    assert original.get_data(a.VirtualAddress, a.Size) == candidate_pe.get_data(b.VirtualAddress, b.Size)
assert [(s.VirtualAddress, s.SizeOfRawData, s.Characteristics) for s in original.sections] == [
    (s.VirtualAddress, s.SizeOfRawData, s.Characteristics) for s in candidate_pe.sections]

CTX = 0x40000000
TABLE = CTX + 0x2000
TRACE = CTX + 0x1000
STUB = 0x50000000
STACK = 0x20000000
STOP = 0x30000000
nv = {r: 0xaabb000000000000+i for i, r in enumerate(range(UC_ARM64_REG_X19, UC_ARM64_REG_X28+1))}
nv[UC_ARM64_REG_FP] = 0xaabbccdd00000029
methods = {'read': (0x8e38, 1, 0x8fc0, 0x8fc4), 'write': (0x8fc8, 2, 0x9150, 0x9154)}

class Machine:
    def __init__(self, pe, base, ready, busy, trace, callback_error):
        self.pe, self.base, self.trace = pe, base, trace
        self.callback_error = callback_error
        self.calls, self.messages = [], []
        self.capture = False
        self.snapshots = []
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.mem_map(base, 0x20000)
        self.uc.mem_write(base, pe.get_memory_mapped_image())
        self.uc.mem_map(CTX, 0x4000)
        self.uc.mem_map(STUB, 0x1000)
        self.uc.mem_map(STACK, 0x10000)
        self.uc.mem_map(STOP, 0x1000)
        self.qword(base+0xc498, TABLE)
        self.qword(base+0xc4c8, 0x12345000)
        self.qword(TABLE+0x650, STUB)
        self.qword(base+0xb110, STUB+0x100)
        self.qword(CTX+0x30, STUB+0x200)
        self.qword(CTX+0x38, STUB+0x300)
        self.qword(base+0xc108, TRACE if trace else base+0xc108)
        self.qword(base+0xc100, TRACE+0x100)
        self.qword(TRACE+0x140, 0x55667700)
        self.uc.mem_write(CTX+0xf0, bytes([ready]))
        self.uc.mem_write(CTX+0x118, struct.pack('<I', busy))
        self.uc.hook_add(UC_HOOK_CODE, self.hook)

    def qword(self, address, value):
        self.uc.mem_write(address, struct.pack('<Q', value))

    def hook(self, cpu, address, size, unused):
        rva = address - self.base
        if self.capture and (0x8e38 <= rva < 0x8fbc or 0x8fc8 <= rva < 0x914c):
            registers = [cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(29)]
            registers += [cpu.reg_read(UC_ARM64_REG_FP), cpu.reg_read(UC_ARM64_REG_LR)]
            self.snapshots.append((rva, cpu.reg_read(UC_ARM64_REG_SP)-(STACK+0x7000),
                                   registers, bytes(cpu.mem_read(STACK+0x7000, 0x2000))))
        lr = cpu.reg_read(UC_ARM64_REG_LR)
        if address == STUB:
            cpu.reg_write(UC_ARM64_REG_X0, CTX)
            cpu.reg_write(UC_ARM64_REG_PC, lr)
        elif address == STUB+0x100:
            cpu.reg_write(UC_ARM64_REG_PC, lr)
        elif address in (STUB+0x200, STUB+0x300):
            assert cpu.reg_read(UC_ARM64_REG_SP) % 16 == 0
            self.calls.append({'kind': 'write' if address == STUB+0x200 else 'read',
                               'register': cpu.reg_read(UC_ARM64_REG_W0),
                               'length': cpu.reg_read(UC_ARM64_REG_W1),
                               'buffer': cpu.reg_read(UC_ARM64_REG_X2)})
            cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X3), struct.pack('<I', self.callback_error))
            for reg in range(UC_ARM64_REG_X0, UC_ARM64_REG_X17+1):
                cpu.reg_write(reg, 0xcccccccccccccccc)
            cpu.reg_write(UC_ARM64_REG_PC, lr)
        elif address == self.base+0x1698:
            self.messages.append({'id': cpu.reg_read(UC_ARM64_REG_W3), 'status': cpu.reg_read(UC_ARM64_REG_W5)})
            cpu.reg_write(UC_ARM64_REG_PC, lr)

    def call(self, method):
        uc = self.uc
        for reg, value in nv.items():
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM64_REG_X18, 0x1818181818181818)
        uc.reg_write(UC_ARM64_REG_SP, STACK+0x8000)
        uc.reg_write(UC_ARM64_REG_LR, STOP)
        uc.reg_write(UC_ARM64_REG_X0, 0x12345678)
        uc.reg_write(UC_ARM64_REG_W1, 0x50)
        uc.reg_write(UC_ARM64_REG_W2, 1)
        uc.reg_write(UC_ARM64_REG_X3, CTX+0x3000)
        start_calls, start_messages = len(self.calls), len(self.messages)
        uc.emu_start(self.base+methods[method][0], STOP, count=1000)
        assert uc.reg_read(UC_ARM64_REG_PC) == STOP
        assert uc.reg_read(UC_ARM64_REG_SP) == STACK+0x8000
        assert all(uc.reg_read(reg) == value for reg, value in nv.items())
        assert uc.reg_read(UC_ARM64_REG_X18) == 0x1818181818181818
        return {'status': uc.reg_read(UC_ARM64_REG_W0),
                'lock': struct.unpack('<I', uc.mem_read(CTX+0x118, 4))[0],
                'calls': self.calls[start_calls:], 'messages': self.messages[start_messages:]}

cases = 0
reproductions = []
for base, method, ready, busy, trace, error in itertools.product(
        (0x140000000, 0x180000000, 0x10000000), methods, (0, 1, 2, 255), (0, 1, 2, 3), (False, True), (0, 0x61, 0xc0000001)):
    before = Machine(original, base, ready, busy, trace, error).call(method)
    after = Machine(candidate_pe, base, ready, busy, trace, error).call(method)
    if ready != 1 and busy == 0:
        assert before['lock'] == methods[method][1] and after['lock'] == 0
        assert before['status'] == after['status'] and before['status'] & 0x80000000
        assert not before['calls'] and not after['calls']
        assert before['messages'] == after['messages']
    else:
        assert before == after, (base, method, ready, busy, trace, error, before, after)
        assert after['lock'] == (busy if busy else 0)
    cases += 1

for pe, label in ((original, 'original'), (candidate_pe, 'candidate')):
    for first, second in itertools.product(methods, methods):
        machine = Machine(pe, 0x140000000, 0, 0, True, 0)
        initial = machine.call(first)
        machine.uc.mem_write(CTX+0xf0, b'\x01')
        retry = machine.call(second)
        if label == 'original':
            assert retry['status'] & 0x80000000 and not retry['calls'] and retry['lock']
        else:
            assert retry['status'] == 0 and retry['lock'] == 0 and len(retry['calls']) == 1
        reproductions.append({'binary': label, 'initialMethod': first, 'retryMethod': second,
                              'initial': initial, 'retryAfterReady': retry})

# Use the already inspected native user-mode unwinder's fixture convention.
STOP = 0x400000
nv = {r: 0xabc0000000000000+i for i, r in enumerate(range(UC_ARM64_REG_X19, UC_ARM64_REG_X28+1))}
nv[UC_ARM64_REG_FP] = 0xabc1234567890000
snapshots = {}
for method, ready, busy, trace, error in itertools.product(methods, (0, 1), (0, 3), (False, True), (0, 0x61)):
    machine = Machine(candidate_pe, 0x140000000, ready, busy, trace, error)
    machine.capture = True
    machine.call(method)
    for pc, sp, registers, memory in machine.snapshots:
        snapshots[(pc, sp, tuple(registers))] = (pc, sp, registers, memory)
with (out / 'unwind-fixtures.bin').open('wb') as stream:
    stream.write(struct.pack('<II', 0x3157444e, len(snapshots)))
    for pc, sp, registers, memory in snapshots.values():
        stream.write(struct.pack('<II31Q', pc, sp, *registers) + memory)

report = {'SourceSHA256': source_hash, 'CandidateSHA256': hashlib.sha256(patched).hexdigest(),
          'CandidateFile': candidate.name, 'Signed': False, 'Installed': False,
          'InstructionPatches': patches, 'ComparedOriginalAndCandidateCases': cases,
          'ReadyAfterNotReadySequences': len(reproductions), 'ASLRBases': 3,
          'PreservedNonvolatileRegisters': True, 'PreservedX18': True, 'StackRestored': True,
          'ExistingBusyOwnerPreserved': True, 'ErrorStatusAndTracePreserved': True,
          'UnwindImportRelocationLoadConfigAndIATUnchanged': True, 'SectionLayoutUnchanged': True,
          'HardwareTested': False, 'RootCauseOfObservedHubLossProven': False,
          'NativeUnwindFixturesPrepared': len(snapshots),
          'Limitation': 'A narrowly scoped lock-release research candidate. Does not change PMIC/OTG/PD policy or fix existing callback-error masking. Emulation cannot establish actual boot/power/concurrency safety.',
          'Reproductions': reproductions}
(out / 'build-and-emulation.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8', newline='\n')
print(json.dumps({k: v for k, v in report.items() if k not in ('Reproductions', 'InstructionPatches')}, indent=2))
