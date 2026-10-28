"""Read-only PE/QA audit. Never loads driver code or opens a device."""
import hashlib, json, struct, sys
from pathlib import Path
sys.path.insert(0, r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
import pefile

ROOT = Path(__file__).resolve().parents[1]
NAMES = ['qcpmictcc8150', 'qcusbctcpm8150', 'qcbattmngr8150']
FINAL = [
    'ca539f2d67564b7ac373e21cd15d5263971296ed74e151984335686af57203a2',
    '6b5b273af895d3f1b0263f0d71a3814ecf7c2c40bb469f53ad0bfcb2d0f254f2',
    '37fa559c599faa92c9981d6d39155e9b8965e29fb714cea700d4de797f22304f',
]
ORIGINAL = [
    'be9850ce5ab8a9e5ead615de592ff8177154bde9496320910210dc503b2b46e9',
    '7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067',
    '3659a20de0606aa7283ea3197a1c212e28bfec212c838914f19d74be629453a3',
]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def check(condition, message):
    if not condition:
        raise RuntimeError(message)

def imports(pe):
    return {(d.dll.lower().decode(), i.name.decode() if i.name else i.ordinal):
            i.address - pe.OPTIONAL_HEADER.ImageBase
            for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports}

def records(pe):
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    return list(struct.iter_unpack('<II', pe.get_data(d.VirtualAddress, d.Size)))

def properties(original, candidate):
    check(candidate.FILE_HEADER.Machine == 0xaa64, 'Not native ARM64')
    for field in ['AddressOfEntryPoint', 'ImageBase', 'Subsystem', 'DllCharacteristics']:
        check(getattr(original.OPTIONAL_HEADER, field) == getattr(candidate.OPTIONAL_HEADER, field),
              'Original loader property changed: ' + field)
    check(candidate.verify_checksum(), 'PE checksum invalid')
    check(not any(s.Characteristics & 0x20000000 and s.Characteristics & 0x80000000
                  for s in candidate.sections), 'Writable executable section')
    old_imports, new_imports = imports(original), imports(candidate)
    check(all(new_imports.get(k) == v for k, v in old_imports.items()), 'Old IAT changed')
    for number in [5, 10, 12]:
        a, b = original.OPTIONAL_HEADER.DATA_DIRECTORY[number], candidate.OPTIONAL_HEADER.DATA_DIRECTORY[number]
        check((a.VirtualAddress, a.Size) == (b.VirtualAddress, b.Size), 'Loader directory moved')
        check(original.get_data(a.VirtualAddress, a.Size) == candidate.get_data(b.VirtualAddress, b.Size),
              'Base relocations / CFG / original IAT changed')
    pd = records(candidate)
    check(pd == sorted(pd) and len({a for a, b in pd}) == len(pd), 'Runtime table order invalid')
    check(set(records(original)) <= set(pd), 'Original runtime record lost')
    return sorted(set(new_imports) - set(old_imports))

def changed_sections(original, candidate, patches):
    expected = bytearray(original.__data__)
    for row in patches:
        rva = int(row['rva'], 16) if isinstance(row['rva'], str) else row['rva']
        at = original.get_offset_from_rva(rva)
        before, after = bytes.fromhex(row['before']), bytes.fromhex(row['after'])
        check(expected[at:at + len(before)] == before, 'Patch preimage mismatch')
        expected[at:at + len(after)] = after
    for section in original.sections:
        other = candidate.get_section_by_rva(section.VirtualAddress)
        check(other is not None and section.Name == other.Name and
              section.Characteristics == other.Characteristics and
              section.Misc_VirtualSize == other.Misc_VirtualSize and
              section.SizeOfRawData == other.SizeOfRawData, 'Stock section metadata changed')
        at, size = section.PointerToRawData, section.SizeOfRawData
        check(expected[at:at + size] == other.get_data(), 'Unlisted stock section change')

def audit():
    compile_record = read_json(ROOT/'build/compile-record.json')
    analysis = read_json(ROOT/'build/analyze-record.json')
    check(analysis['passed'] and analysis['warningAsError'] and analysis['kernel'], 'Analyzer failed')
    check(compile_record['sources'] == analysis['sources'] and
          compile_record['compiler'] == analysis['compiler'], 'Analyzer/build identity differs')
    for row in compile_record['sources']:
        check(digest(ROOT/'src'/row['name']) == row['sha256'].lower(), 'Source changed since build')
    for row in compile_record['objects']:
        check(digest(ROOT/'build'/row['name']) == row['sha256'].lower(), 'Compiled object changed')
    for row in read_json(ROOT/'support/provenance.json'):
        check(digest(ROOT/'support'/row['path']) == row['sha256'].lower(), 'Support preimage changed')

    backend, client = [read_json(ROOT/f'build/{k}-build.json') for k in ['backend', 'client']]
    for kind, meta in [('backend', backend), ('client', client)]:
        check(digest(ROOT/f'build/{kind}_repair.obj') == meta['objectSHA256'], 'PE/object identity differs')
    client_policy = read_json(ROOT/'build/qcusbctcpm8150.policy.json')
    battery_policy = read_json(ROOT/'build/qcbattmngr8150.policy.json')
    check(client_policy['baseNativeSHA256'] == client['unsignedSHA256'], 'Client intermediate identity differs')
    check(backend['unsignedSHA256'] == FINAL[0] and client_policy['unsignedSHA256'] == FINAL[1] and
          battery_policy['unsignedSHA256'] == FINAL[2], 'Final build identity differs')
    rows = []
    for name, expected, original_hash, patches in zip(NAMES, FINAL, ORIGINAL, [
        backend['hooks'], client['hooks'] + client_policy['transportPatches'] + client_policy['patches'],
        battery_policy['patches'],
    ]):
        path, original_path = ROOT/f'build/{name}.sys', ROOT/f'reference/{name}.sys'
        check(digest(path) == expected and digest(original_path) == original_hash, 'Pinned binary mismatch')
        stock, pe = pefile.PE(str(original_path)), pefile.PE(str(path))
        extra = properties(stock, pe)
        check(extra == ([('ntoskrnl.exe', 'ZwWaitForSingleObject')] if name == NAMES[0] else []),
              'Unexpected new import')
        changed_sections(stock, pe, patches)
        rows.append(dict(name=name, unsignedSHA256=expected, originalSHA256=original_hash,
                         stockSectionsOnlyListedPatches=True, originalLoaderAndUnwindPreserved=True,
                         newImports=extra, noWritableExecutableSections=True))
    totals = {}
    for name, kind, expected, count in zip(NAMES, ['backend', 'client', 'battery'], FINAL, [282, 3528, 93]):
        qa = read_json(ROOT/f'build/{kind}-emulation.json')
        check(qa['sha256'] == expected and qa['cases'] == count and qa['actualPatchedPE'] and
              qa['ddiMocks'] and not qa['hardwareAccess'] and not qa['kernelExecution'], 'Emulation identity/coverage mismatch')
        if kind == 'client':
            check(qa['fullCleanupCases'] == 90 and qa['fullD0ExitCases'] == 270 and
                  qa['nativeFlushExecuted'] and qa['nativeYieldExecuted'], 'Client drain coverage missing')
            totals.update(clientFullCleanup=90, clientFullD0Exit=270)
        totals[kind] = count
    unwind = read_json(ROOT/'build/unwind-identity.json')
    for row in unwind['inputs']:
        check(digest(ROOT/'build'/row['name']) == row['sha256'].lower(), 'Unwind input changed')
    check(digest(ROOT/'tests/native_unwind.c') == unwind['testSourceSHA256'].lower(), 'Unwind test changed')
    for kind, count in [('backend', 4060), ('client', 772)]:
        proof = read_json(ROOT/f'build/{kind}-leaf-unwind-proof.json')
        check(proof['noStackOrNonvolatileWrites'] and proof['noLinkRegisterChanges'] and proof['noCalls'],
              'Missing omitted-leaf proof')
        result = unwind[kind]
        check(result['nativeARM64UnwindCases'] == count and result['failures'] == 0 and
              not result['kernelDriverLoaded'] and not result['mappedDriverMemoryExecutable'], 'Native unwind failed')
    totals.update(nativeUnwind=4832, nativeUnwindFailures=0)
    report = dict(status='OFFLINE_QA_PASSED_NOT_HARDWARE_TESTED', binaries=rows, coverage=totals,
                  hardwareTested=False, kernelExecuted=False, installed=False,
                  kernelSmpAndWdfNotTested=True, completeChargingFixProven=False,
                  evidence={str(p.relative_to(ROOT)).replace('\\', '/'): digest(p)
                            for folder in ['src', 'tools', 'tests', 'support']
                            for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts},
                  qaReports={str(p.relative_to(ROOT)).replace('\\', '/'): digest(p)
                             for p in (ROOT/'build').glob('*.json') if p.name != 'qa-identity.json'})
    (ROOT/'build/qa-identity.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'status': report['status'], 'coverage': totals}, indent=2))

def signed_payload():
    qa = read_json(ROOT/'build/qa-identity.json')
    checks = []
    for name, expected in zip(NAMES, FINAL):
        path = ROOT/f'build/{name}.sys'
        check(digest(path) == expected, 'Unsigned input changed')
        unsigned, signed = pefile.PE(str(path)), pefile.PE(str(ROOT/f'package/{name}.sys'))
        check(signed.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0, 'Missing embedded signature')
        check(signed.verify_checksum(), 'Signed checksum invalid')
        # Only checksum and security-directory fields may differ before the certificate overlay.
        a, b = bytearray(unsigned.__data__), bytearray(signed.__data__[:len(unsigned.__data__)])
        for at, length in [(unsigned.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'), 4),
                           (unsigned.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(), 8)]:
            a[at:at+length] = b'\0' * length
            b[at:at+length] = b'\0' * length
        check(a == b, 'Signing changed pre-overlay bytes')
        check(len(unsigned.sections) == len(signed.sections), 'Signing changed section count')
        for x, y in zip(unsigned.sections, signed.sections):
            check(x.__pack__() == y.__pack__() and x.get_data() == y.get_data(), 'Signing changed mapped section')
        properties(unsigned, signed)
        check(imports(unsigned) == imports(signed) and records(unsigned) == records(signed), 'Signing changed ABI')
        checks.append(dict(name=name, unsignedSHA256=expected, signedSHA256=digest(ROOT/f'package/{name}.sys'),
                           allMappedSectionsByteIdentical=True, onlyChecksumSecurityDirectoryOverlayChanged=True))
    report = dict(qaIdentitySHA256=digest(ROOT/'build/qa-identity.json'), binaries=checks,
                  signaturePreservedTestedPayload=True, hardwareTested=False, installed=False)
    (ROOT/'build/signed-payload-identity.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('Signed mapped payload is identical to the tested unsigned payload (3 SYS).')

if __name__ == '__main__':
    signed_payload() if '--signed' in sys.argv else audit()
