"""Bind final1853 client, sources, compiler, emulation, CFG and native unwind.
All verification is offline. No driver/service/PnP/device APIs are invoked.
"""
import hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
import pefile
from audit_package import changed_sections,imports,records,check

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def gfids(pe):
    lc=pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    check(lc.GuardFlags>>28==0,'Unexpected CFG stride')
    return list(struct.unpack('<'+'I'*lc.GuardCFFunctionCount,
        pe.get_data(lc.GuardCFFunctionTable-pe.OPTIONAL_HEADER.ImageBase,lc.GuardCFFunctionCount*4)))

def audit():
    compiled=read(ROOT/'build/compile-record.json');analysis=read(ROOT/'build/analyze-record.json')
    check(analysis['passed'] and analysis['warningAsError'] and analysis['kernel'],'Analyzer did not pass')
    check(compiled['sources']==analysis['sources'] and compiled['compiler']==analysis['compiler'],'Analyzer/source mismatch')
    for row in compiled['sources']:check(digest(ROOT/'src'/row['name'])==row['sha256'].lower(),'Source changed since compile')
    for row in compiled['objects']:check(digest(ROOT/'build'/row['name'])==row['sha256'].lower(),'Object changed since compile')
    for row in read(ROOT/'support/provenance.json'):
        check(digest(ROOT/'support'/row['path'])==row['sha256'].lower(),'Reference test support changed')
    meta=read(ROOT/'build/client-build.json');policy=read(ROOT/'build/qcusbctcpm8150.policy.json')
    path=ROOT/'build/qcusbctcpm8150.sys';expected=digest(path)
    check(meta['objectSHA256']==digest(ROOT/'build/client_repair.obj'),'PE/object mismatch')
    check(policy['baseNativeSHA256']==meta['unsignedSHA256'] and policy['unsignedSHA256']==expected,'Native/policy mismatch')
    ref=ROOT/'reference/qcusbctcpm8150.sys'
    check(digest(ref)=='7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067','Unrecognized original')
    stock=pefile.PE(data=ref.read_bytes());pe=pefile.PE(data=path.read_bytes())
    check(pe.verify_checksum() and pe.FILE_HEADER.Machine==0xaa64,'ARM64 PE/checksum invalid')
    for field in ['AddressOfEntryPoint','ImageBase','Subsystem','DllCharacteristics']:
        check(getattr(pe.OPTIONAL_HEADER,field)==getattr(stock.OPTIONAL_HEADER,field),'Loader field changed: '+field)
    check(not any(s.Characteristics&0x20000000 and s.Characteristics&0x80000000 for s in pe.sections),'RWX section')
    check(imports(stock)==imports(pe),'Unexpected import or IAT change')
    for n in [5,12]:
        a,b=stock.OPTIONAL_HEADER.DATA_DIRECTORY[n],pe.OPTIONAL_HEADER.DATA_DIRECTORY[n]
        check((a.VirtualAddress,a.Size)==(b.VirtualAddress,b.Size) and stock.get_data(a.VirtualAddress,a.Size)==pe.get_data(b.VirtualAddress,b.Size),'Relocation/IAT directory changed')
    changed_sections(stock,pe,meta['hooks']+meta['loaderPatches']+policy['transportPatches']+policy['patches'])
    check(set(records(stock))<=set(records(pe)),'Original unwind record lost')
    pd=records(pe);check(pd==sorted(pd) and len({r for r,u in pd})==len(pd),'Unsorted/duplicate unwind entry')
    callbacks=[meta['symbols'][name] for name in ['RepairD0Entry','RepairD0Exit','RepairPrepareHardware','RepairProvider']]
    check(gfids(pe)==sorted(set(gfids(stock))|set(callbacks)),'New WDF callbacks missing from CFG')
    check(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags==stock.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags,'CFG flags changed')
    leaf=read(ROOT/'build/client-leaf-unwind-proof.json')
    proven_leaves={r['rva'] for r in leaf['leaves']}
    # ARM64 shrink wrapping may keep a stackless admission prefix before the
    # first runtime record. Such an entry must be a proven leaf instruction,
    # and every observed prologue/body/epilogue is checked by native unwind.
    runtime_starts={r for r,u in pd}
    check(set(callbacks)<=runtime_starts|proven_leaves,'Callback has neither runtime unwind nor a proven leaf prefix')
    aslr=[]
    for newbase in [0x180000000,0x7ffb12340000]:
        relocated=pefile.PE(data=path.read_bytes());relocated.relocate_image(newbase)
        lc=relocated.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        check(lc.GuardCFFunctionTable==newbase+meta['cfgTableRVA'],'CFG VA not relocated')
        check(gfids(relocated)==gfids(pe),'ASLR changed CFG function RVAs')
        aslr.append(hex(newbase))
    emu=read(ROOT/'build/client-emulation.json');alerts=read(ROOT/'build/alert-lifecycle-emulation.json')
    provider=read(ROOT/'build/provider-emulation.json')
    check(emu['sha256']==expected and emu['cases']==3528 and emu['fullCleanupCases']==90 and emu['fullD0ExitCases']==270,'Client regression identity/coverage mismatch')
    check(emu['permanentOwnerProtected'] and emu['nativeFlushExecuted'] and emu['nativeYieldExecuted'],'Drain regression incomplete')
    check(alerts['sha256']==expected and alerts['cases']>=96 and alerts['original0x7eNullContextPathBlocked'] and alerts['actualStartStopAdaptersExecuted'] and alerts['actualBackend1851Executed'],'Alert regression identity/coverage mismatch')
    for q in [emu,alerts]:check(not q['kernelExecution'] and not q.get('hardwareIO',q.get('hardwareAccess',False)),'Unexpected live test')
    check(provider['sha256']==expected and provider['cases']==57 and provider['heldInterfaceCounterexampleBlocked'] and
          provider['originalPrepareAndReleaseBodiesExecuted'] and provider['originalInterfaceRegistrationExecuted'] and
          provider['actualOriginalProviderExecuted'] and provider['failedMapReturnStatusCorrect'] and
          not provider['nullOrDoubleUnmap'] and not provider['kernelExecuted'] and not provider['installed'],
          'Provider test identity/coverage mismatch')
    check(provider['testSourceSHA256']==digest(ROOT/'tests/test_provider_pe.py'),'Provider test source changed')
    joint=read(ROOT/'build/pep-client-joint.json')
    pep_lab=ROOT.parent/'candidate-1852-alert-rundown/next-pep'
    check(joint['clientSHA256']==expected and joint['cases']==8 and joint['providerLateMMIOCounterexampleBlocked'] and
          joint['actualInterfaceRegistrationAndReferenceCallbacks'] and joint['actualPEPNotifyBody'] and
          not joint['kernelExecuted'] and not joint['installed'],'Joint PEP/client test failed')
    check(joint['testSourceSHA256']==digest(ROOT/'tests/test_pep_client_joint.py') and
          joint['harnessSHA256']==digest(pep_lab/'test_lab.py') and
          joint['pepSourceSHA256'].lower()==digest(pep_lab/'pep_lifetime.c') and
          joint['pepObjectSHA256'].lower()==digest(pep_lab/'build/pep_lifetime.obj'),'Joint dependency changed')
    unwind=read(ROOT/'build/unwind-identity.json')
    for row in unwind['inputs']:check(digest(ROOT/'build'/row['name'])==row['sha256'].lower(),'Native unwind input changed')
    check(digest(ROOT/'tests/native_unwind.c')==unwind['testSourceSHA256'].lower(),'Unwind test changed')
    leaf=read(ROOT/'build/client-leaf-unwind-proof.json')
    check(leaf['noStackOrNonvolatileWrites'] and leaf['noLinkRegisterChanges'] and leaf['noCalls'],'Leaf proof failed')
    for name in ['client','alert','provider']:
        result=unwind['reports'][name]
        check(result['failures']==0 and result['nativeARM64UnwindCases']>0 and not result['kernelDriverLoaded'] and not result['mappedDriverMemoryExecutable'],'Native unwind failed')
        count=emu['fixtureCount'] if name=='client' else (alerts['fixtures'] if name=='alert' else provider['fixtures'])
        check(count==result['nativeARM64UnwindCases'],'Unwind fixture coverage mismatch')
    repro=read(ROOT/'build/reproducibility.json')
    check(repro['identical'] and repro['unsignedSHA256']==expected and repro['objectSHA256']==meta['objectSHA256'],'Rebuild was not identical')
    report=dict(name='SK-Charging-1853-provider-rundown',status='OFFLINE_QA_PASSED_HARDWARE_BLOCKED',
        unsignedSHA256=expected,objectSHA256=meta['objectSHA256'],newCfgCallbacks=callbacks,ASLRChecked=aslr,
        callbackUnwindModes={hex(r):('runtime-record' if r in runtime_starts else 'verified-stackless-prefix') for r in callbacks},
        coverage=dict(transport=3528,originalCleanup=90,originalD0Exit=270,alertLifecycle=alerts['cases'],providerLifecycle=provider['cases'],jointPepClient=joint['cases'],
            nativeUnwind=sum(r['nativeARM64UnwindCases'] for r in unwind['reports'].values())),
        sourceAndTestHashes={str(p.relative_to(ROOT)).replace('\\','/'):digest(p)
            for folder in ['src','tools','tests','support'] for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts},
        qaReports={p.name:digest(p) for p in (ROOT/'build').glob('*.json') if p.name not in ['qa-1853.json','signed-payload-1853.json']},
        installed=False,bootTested=False,kernelExecuted=False,physicalSMPTested=False,chargingFixProven=False,
        knownBlockers=['Unfixed PEP2140 0x13A lifetime fault','Initial pending-alert replay and single-producer audit remain open','Initial PEP power request retry after DEVICE_NOT_READY not implemented','Electrical PD and storage continuity untested','Ghost AC reporting not fixed by this client-only build'])
    (ROOT/'build/qa-1853.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['status','unsignedSHA256','coverage']},indent=2))

def signed():
    qa=read(ROOT/'build/qa-1853.json')
    source=ROOT/'build/qcusbctcpm8150.sys';path=ROOT/'package/qcusbctcpm8150.sys'
    check(digest(source)==qa['unsignedSHA256'],'Tested unsigned image changed')
    unsigned=pefile.PE(data=source.read_bytes());pe=pefile.PE(data=path.read_bytes())
    check(pe.verify_checksum() and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size>0,'Signed PE invalid')
    a=bytearray(source.read_bytes());b=bytearray(path.read_bytes()[:len(a)])
    for off,size in [(unsigned.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),4),(unsigned.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(),8)]:
        a[off:off+size]=bytes(size);b[off:off+size]=bytes(size)
    check(a==b,'Signature changed tested payload')
    check(len(unsigned.sections)==len(pe.sections),'Section count changed after signing')
    for x,y in zip(unsigned.sections,pe.sections):check(x.__pack__()==y.__pack__() and x.get_data()==y.get_data(),'Signature changed mapped section')
    check(gfids(pe)==gfids(unsigned) and records(pe)==records(unsigned) and imports(pe)==imports(unsigned),'Signature changed CFG/unwind/IAT')
    report=dict(unsignedSHA256=digest(source),signedSHA256=digest(path),allMappedSectionsIdentical=True,
                qaSHA256=digest(ROOT/'build/qa-1853.json'),installed=False,hardwareTested=False)
    (ROOT/'build/signed-payload-1853.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('Signed1853 mapped payload matches offline-tested image.')
if __name__=='__main__':signed() if '--signed' in sys.argv else audit()
