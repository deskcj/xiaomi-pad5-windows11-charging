"""Constrained, hash-pinned native COFF to Qualcomm ARM64 PE binder.
Unknown sections/symbols/relocations fail. Never installs or opens devices.
"""
import hashlib,json,struct,sys
from pathlib import Path
sys.path.insert(0,r'H:\Vlad\Charging\research\2026-10-26\tools\python-deps')
import pefile
ROOT=Path(__file__).resolve().parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
align=lambda n,a:(n+a-1)//a*a
def signed(n,b):return n-(1<<b) if n&(1<<(b-1)) else n
def branch(at,to,link=False):
    d=to-at;assert d%4==0 and -(1<<27)<=d<(1<<27)
    return (0x94000000 if link else 0x14000000)|((d//4)&0x3ffffff)

def coff(data):
    machine,n,_,symoff,nsym,opt,_=struct.unpack_from('<HHIIIHH',data)
    assert machine==0xaa64 and opt==0
    strings=data[symoff+nsym*18:]
    def name(v):
        if v[:4]==b'\0'*4:return strings[struct.unpack_from('<I',v,4)[0]:].split(b'\0',1)[0].decode()
        v=v.split(b'\0',1)[0].decode()
        return strings[int(v[1:]):].split(b'\0',1)[0].decode() if v.startswith('/') else v
    sections=[]
    for i in range(n):
        nm,vs,va,size,raw,rel,ln,nrel,nln,flags=struct.unpack_from('<8sIIIIIIHHI',data,20+40*i)
        sections.append(dict(index=i+1,name=name(nm),data=bytearray(data[raw:raw+size]) if raw else bytearray(size),
                             relocs=[struct.unpack_from('<IIH',data,rel+10*j) for j in range(nrel)],flags=flags))
    symbols=[None]*nsym;i=0
    while i<nsym:
        nm,value,section,typ,storage,aux=struct.unpack_from('<8sIhHBB',data,symoff+18*i)
        symbols[i]=dict(name=name(nm),value=value,section=section,type=typ,storage=storage)
        i+=1+aux
    return sections,symbols

def build(kind='backend'):
    assert kind in ['backend','client']
    binary='qcpmictcc8150.sys' if kind=='backend' else 'qcusbctcpm8150.sys'
    stock=(ROOT/'reference'/binary).read_bytes()
    expected='be9850ce5ab8a9e5ead615de592ff8177154bde9496320910210dc503b2b46e9' if kind=='backend' else '7c63f4a4b8a9ee0f49b427b6ac94867d2475e02f85d92d5fbcfe4a8aa1804067'
    assert sha(stock)==expected
    obj=(ROOT/f'build/{kind}_repair.obj').read_bytes();sections,symbols=coff(obj)
    pe=pefile.PE(data=stock);base=pe.OPTIONAL_HEADER.ImageBase
    assert pe.FILE_HEADER.Machine==0xaa64
    ext={'SkWdfTable':0x1a6d8,'SkWdfGlobals':0x1a708,'SkContextType':0x1a098,
         'SkAdcTarget':0x1aa30,'SkAdcReady':0x1aa40,'SkPmicTarget':0x1aa18,'SkPmicReady':0x1aa28,
         'SkDriverActive':0x1a81c,'SkThreadHandle':0x1a820,
         'OriginalSetPower':0x8af8,'OriginalCommand99':0x8f08,
         'OriginalDispatch':0x10c68,'OriginalWppInitialize':0x1c4f8,
         'OriginalTransmit':0x7618,'OriginalRoleControl':0x7148,'OriginalPowerControl':0x6ec8,
         'OriginalAlertMask':0x64a0,'OriginalReceiveDetect':0x6088,'OriginalMessageHeader':0x7388,
         'OriginalPendingAck':0xf988,'OriginalWriteVirtual':0xf178,
         'OriginalResetBackend':0x2370,
         '__guard_check_icall_fptr':0x18160,'__security_push_cookie':0x1050,
         '__security_pop_cookie':0x1068,'__GSHandlerCheck':0x17150}
    if kind=='client':ext={'SkWdfTable':0xc498,'SkWdfGlobals':0xc4c8,'SkContextType':0xc128,
                           'SkClassAlert':0xc270,'SkClassGlobals':0xc278,
                           'OriginalD0Entry':0x1c10,'OriginalD0Exit':0x1e50,
                           '__guard_check_icall_fptr':0xb110}
    for d in pe.DIRECTORY_ENTRY_IMPORT:
        for i in d.imports:
            if i.name:ext['__imp_'+i.name.decode()]=i.address-base
    allowed={'.text$mn','.text','.bss','.data','.rdata','.xdata','.pdata'}
    ignored={'.drectve','.debug$S','.debug$T','.chks64','.gfids$y','.giats$y','.gljmp$y'}
    assert all(s['name'] in allowed|ignored or not s['data'] for s in sections)
    code_rva=align(pe.OPTIONAL_HEADER.SizeOfImage,4096);cursor=code_rva;placements={}
    texts=[s for s in sections if s['name'].startswith('.text') and s['data']]
    for s in texts:
        cursor=align(cursor,16);placements[s['index']]=cursor;cursor+=len(s['data'])
    meta_rva=align(cursor,4096);cursor=meta_rva
    ro=[s for s in sections if s['name'] in {'.rdata','.xdata'} and s['data']]
    for s in ro:
        cursor=align(cursor,16);placements[s['index']]=cursor;cursor+=len(s['data'])
    old_pd=pe.get_data(pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress,pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size)
    pdatas=[s for s in sections if s['name']=='.pdata' and s['data']]
    pd_rva=align(cursor,8);cursor=pd_rva+len(old_pd)
    for s in pdatas:
        placements[s['index']]=cursor;cursor+=len(s['data'])
    # Extend the import directory with one ntoskrnl descriptor. Existing IAT
    # addresses stay unchanged, including WDF and loader-owned CFG pointers.
    imports=[d.struct.__pack__() for d in pe.DIRECTORY_ENTRY_IMPORT]
    imp_rva=align(cursor,8);imp_bytes=bytearray(20*(len(imports)+2));cursor=imp_rva+len(imp_bytes)
    dll_rva=cursor;dll=b'ntoskrnl.exe\0';cursor+=len(dll)
    new_import='ZwWaitForSingleObject' if kind=='backend' else 'KeDelayExecutionThread'
    add_import='__imp_'+new_import not in ext
    name_rva=align(cursor,2);nm=b'\0\0'+new_import.encode()+b'\0';cursor=name_rva+len(nm)
    ilt_rva=align(cursor,8);cursor=ilt_rva+16
    # WDF calls these two callbacks indirectly. Keep every original CFG entry
    # and add the new compiler-described entry points to the sorted GFIDS table.
    cfg_table=None;cfg_rva=0;cfg_callbacks=[]
    if kind=='client':
        lc=pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        assert (lc.GuardFlags>>28)==0,'Unsupported CFG entry metadata stride'
        old_cfg=pe.get_data(lc.GuardCFFunctionTable-base,lc.GuardCFFunctionCount*4)
        cfg_callbacks=[next(placements[s['section']]+s['value'] for s in symbols if s and s['name']==name)
                       for name in ['RepairD0Entry','RepairD0Exit']]
        cfg_entries=sorted(set(struct.unpack('<'+'I'*lc.GuardCFFunctionCount,old_cfg))|set(cfg_callbacks))
        assert len(cfg_entries)==lc.GuardCFFunctionCount+2
        cfg_table=struct.pack('<'+'I'*len(cfg_entries),*cfg_entries)
        cfg_rva=align(cursor,4);cursor=cfg_rva+len(cfg_table)
    # IAT needs writable backing, separate from RX code and read-only unwind.
    data_rva=align(cursor,4096);dc=data_rva
    rw=[s for s in sections if s['name'] in {'.bss','.data'} and s['data']]
    for s in rw:
        dc=align(dc,16);placements[s['index']]=dc;dc+=len(s['data'])
    new_iat=align(dc,8);dc=new_iat+16
    if add_import:ext['__imp_'+new_import]=new_iat
    relocations=[]
    for s in texts+ro+pdatas+rw:
        for off,si,rk in s['relocs']:
            sym=symbols[si];assert sym is not None
            if sym['section']>0:
                assert sym['section'] in placements,(sym,rk)
                target=placements[sym['section']]+sym['value']
            else:
                assert sym['section']==0 and sym['name'] in ext,('Unknown external',sym)
                target=ext[sym['name']]
            place=placements[s['index']]+off;word=struct.unpack_from('<I',s['data'],off)[0]
            if rk==2:word=(word+target)&0xffffffff
            elif rk==3:word=branch(place,target+signed(word&0x3ffffff,26)*4,bool(word&0x80000000))
            elif rk==4:
                # COFF stores the unrelocated ADRP addend in BYTES. Only the
                # final instruction immediate is measured in 4KB pages.
                addend=signed((((word>>5)&0x7ffff)<<2)|((word>>29)&3),21)
                delta=((target+addend)&~4095)-(place&~4095)
                assert -(1<<32)<=delta<(1<<32)
                imm=(delta//4096)&0x1fffff
                word=(word&~((0x7ffff<<5)|(3<<29)))|((imm&3)<<29)|((imm>>2)<<5)
            elif rk in [6,7]:
                scale=0 if rk==6 else (word>>30)&3
                assert rk!=6 or not word&(1<<22)
                addend=((word>>10)&0xfff)<<scale;value=(target+addend)&0xfff
                assert value%(1<<scale)==0
                word=(word&~(0xfff<<10))|((value>>scale)<<10)
            else:raise AssertionError(('Unhandled ARM64 relocation',rk,sym))
            struct.pack_into('<I',s['data'],off,word)
            relocations.append(dict(section=s['index'],offset=off,kind=rk,symbol=sym['name'],target=target))
    code=bytearray(meta_rva-code_rva)
    for s in texts:
        off=placements[s['index']]-code_rva;code[off:off+len(s['data'])]=s['data']
    meta=bytearray(cursor-meta_rva)
    for s in ro:
        off=placements[s['index']]-meta_rva;meta[off:off+len(s['data'])]=s['data']
    records=list(struct.iter_unpack('<II',old_pd))
    records+=list(struct.iter_unpack('<II',b''.join(s['data'] for s in pdatas)))
    records.sort();assert len({a for a,b in records})==len(records)
    pd=b''.join(struct.pack('<II',*r) for r in records)
    meta[pd_rva-meta_rva:pd_rva-meta_rva+len(pd)]=pd
    for i,d in enumerate(imports):imp_bytes[20*i:20*(i+1)]=d
    if add_import:struct.pack_into('<IIIII',imp_bytes,20*len(imports),ilt_rva,0,0,dll_rva,new_iat)
    for r,b in [(imp_rva,imp_bytes),(dll_rva,dll),(name_rva,nm),(ilt_rva,struct.pack('<QQ',name_rva,0))]:
        meta[r-meta_rva:r-meta_rva+len(b)]=b
    if cfg_table is not None:meta[cfg_rva-meta_rva:cfg_rva-meta_rva+len(cfg_table)]=cfg_table
    data=bytearray(dc-data_rva)
    for s in rw:
        off=placements[s['index']]-data_rva;data[off:off+len(s['data'])]=s['data']
    struct.pack_into('<QQ',data,new_iat-data_rva,name_rva,0)
    raw_end=max(s.PointerToRawData+s.SizeOfRawData for s in pe.sections)
    result=bytearray(stock[:raw_end]);loader_patches=[]
    if cfg_table is not None:
        lc=pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        pointer_offset=lc.get_field_absolute_offset('GuardCFFunctionTable')
        pointer_rva=pe.get_rva_from_offset(pointer_offset)
        # Reuse the loader's existing DIR64 relocation at this VA field.
        assert any(e.rva==pointer_rva and e.type==10 for block in pe.DIRECTORY_ENTRY_BASERELOC for e in block.entries)
        struct.pack_into('<Q',result,pointer_offset,base+cfg_rva)
        struct.pack_into('<Q',result,lc.get_field_absolute_offset('GuardCFFunctionCount'),len(cfg_table)//4)
        for field in ['GuardCFFunctionTable','GuardCFFunctionCount']:
            off=lc.get_field_absolute_offset(field)
            loader_patches.append(dict(rva=pe.get_rva_from_offset(off),name=field,
                before=stock[off:off+8].hex(),after=bytes(result[off:off+8]).hex()))
    symbols_by_name={s['name']:placements[s['section']]+s['value'] for s in symbols if s and s['section'] in placements}
    hooks={0xa578:'RepairReadAdc',0xaf20:'RepairPowerIo',0x69d0:'RepairCommand',
           0x4ed0:'RepairSourceTimer',0x107a8:'RepairStop',0x100a0:'RepairDispatch',0x1d050:'RepairInitialize',
           0x3550:'RepairExecutePending',0xfedc:'RepairThreadIdentity',0x13f54:'RepairResetBackend'}
    if kind=='client':hooks={0x12fb4:'RepairClientFlush',0x11278:'RepairClientYield',0x12ff0:'RepairClientYield',0x89e0:'RepairClientAlert'}
    changes=[]
    for at,n in hooks.items():
        before=pe.get_data(at,4)
        if at in [0x100a0,0x1d050]:
            expected=0x10c68 if at==0x100a0 else 0x1c4f8
            assert struct.unpack('<I',before)[0]==branch(at,expected,True)
        if kind=='client' and at!=0x89e0:assert struct.unpack('<I',before)[0] in [0xd63f0260,0xd63f0100]
        if kind=='client' and at==0x89e0:assert before==bytes.fromhex('f353bca9')
        if at==0xfedc:assert struct.unpack('<I',before)[0]==0xd63f0100
        if at==0x13f54:assert struct.unpack('<I',before)[0]==0xd63f0260
        after=struct.pack('<I',branch(at,symbols_by_name[n],(kind=='client' and at!=0x89e0) or at in [0x100a0,0x1d050,0xfedc,0x13f54]))
        result[pe.get_offset_from_rva(at):pe.get_offset_from_rva(at)+4]=after
        changes.append(dict(rva=at,name=n,target=symbols_by_name[n],before=before.hex(),after=after.hex()))
    adapters=[]
    if kind=='client':
        stub=align(max(placements[s['index']]+len(s['data']) for s in texts),16)
        # Tail adapters preserve SP/LR/nonvolatile registers and enter a normal
        # compiler-described C function. The first call-site BL owns LR.
        for site,name,words in [
            (0xfd74,'RepairClassStart',[0xaa1a03e2,0xaa1303e3]),
            (0x12f8c,'RepairClassStop',[0xaa1303e2])]:
            before=pe.get_data(site,4);assert before==bytes.fromhex('60023fd6')
            payload=b''.join(struct.pack('<I',w) for w in words)
            payload+=struct.pack('<I',branch(stub+len(payload),symbols_by_name[name]))
            assert stub+len(payload)<=meta_rva,'Adapter exceeds code allocation'
            code[stub-code_rva:stub-code_rva+len(payload)]=payload
            after=struct.pack('<I',branch(site,stub,True))
            result[pe.get_offset_from_rva(site):pe.get_offset_from_rva(site)+4]=after
            changes.append(dict(rva=site,name=name,target=stub,before=before.hex(),after=after.hex()))
            adapters.append(dict(rva=stub,size=len(payload),target=symbols_by_name[name],name=name))
            stub=align(stub+len(payload),4)
        # Replace only WDF PnP callback-address construction. Original callback
        # bodies stay available to the wrappers with their original unwind.
        for site,name,old_rva,rd,rn in [(0xe158,'RepairD0Exit',0x1e50,8,8),
                                      (0xe160,'RepairD0Entry',0x1c10,9,9)]:
            before=pe.get_data(site,8)
            old_page,old_add=struct.unpack('<II',before)
            assert old_page==(0xf0ffff88 if site==0xe158 else 0xf0ffff89)
            assert old_add==0x91000000|((old_rva&4095)<<10)|(rn<<5)|rd
            target=symbols_by_name[name]
            page=((target&~4095)-(site&~4095))//4096
            assert -(1<<20)<=page<(1<<20)
            imm=page&0x1fffff
            adrp=0x90000000|((imm&3)<<29)|((imm>>2)<<5)|rn
            add=0x91000000|((target&4095)<<10)|(rn<<5)|rd
            after=struct.pack('<II',adrp,add)
            result[pe.get_offset_from_rva(site):pe.get_offset_from_rva(site)+8]=after
            changes.append(dict(rva=site,name=name,target=target,before=before.hex(),after=after.hex()))
    st=pe.sections[0].get_file_offset();assert st+40*(len(pe.sections)+3)<=pe.OPTIONAL_HEADER.SizeOfHeaders
    new_sections=[]
    for i,(nm,rva,payload,flags) in enumerate([(b'.skcode',code_rva,code,0x60000020),
                                          (b'.skmeta',meta_rva,meta,0x40000040),(b'.skdata',data_rva,data,0xc0000040)]):
        raw=align(len(result),512);result+=b'\0'*(raw-len(result));raw_size=align(len(payload),512)
        result+=payload+b'\0'*(raw_size-len(payload))
        sh=struct.pack('<8sIIIIIIHHI',nm.ljust(8,b'\0'),len(payload),rva,raw_size,raw,0,0,0,0,flags)
        result[st+40*(len(pe.sections)+i):st+40*(len(pe.sections)+i+1)]=sh
        new_sections.append(dict(name=nm.decode(),rva=rva,size=len(payload),flags=flags))
    def opt(n,v):struct.pack_into('<I',result,pe.OPTIONAL_HEADER.get_field_absolute_offset(n),v)
    def directory(i,r,s):struct.pack_into('<II',result,pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].get_file_offset(),r,s)
    struct.pack_into('<H',result,pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),len(pe.sections)+3)
    opt('SizeOfImage',align(dc,4096));opt('SizeOfCode',pe.OPTIONAL_HEADER.SizeOfCode+align(len(code),512))
    opt('SizeOfInitializedData',pe.OPTIONAL_HEADER.SizeOfInitializedData+align(len(meta),512)+align(len(data),512))
    directory(1,imp_rva,len(imp_bytes));directory(3,pd_rva,len(pd));directory(4,0,0)
    opt('CheckSum',0);opt('CheckSum',pefile.PE(data=bytes(result)).generate_checksum())
    built=pefile.PE(data=bytes(result));assert built.verify_checksum()
    assert built.OPTIONAL_HEADER.AddressOfEntryPoint==pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for i in [5,12]+([10] if kind!='client' else []):
        d=pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
        assert built.get_data(d.VirtualAddress,d.Size)==pe.get_data(d.VirtualAddress,d.Size)
    assert len(built.DIRECTORY_ENTRY_IMPORT)==len(pe.DIRECTORY_ENTRY_IMPORT)+int(add_import)
    if add_import:assert built.DIRECTORY_ENTRY_IMPORT[-1].imports[0].name==new_import.encode()
    assert not any(s.Characteristics&0x20000000 and s.Characteristics&0x80000000 for s in built.sections)
    if cfg_table is not None:
        lc=built.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        assert lc.GuardFlags==pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags
        assert built.get_data(lc.GuardCFFunctionTable-base,lc.GuardCFFunctionCount*4)==cfg_table
    out=ROOT/'build'/binary;out.write_bytes(result)
    report=dict(name='SK-Charging-1852-'+kind,status='BUILT_NOT_VALIDATED',originalSHA256=sha(stock),
                objectSHA256=sha(obj),unsignedSHA256=sha(result),hooks=changes,sections=new_sections,
                loaderPatches=loader_patches,
                symbols=symbols_by_name,external=ext,relocations=relocations,adapters=adapters,
                compilerUnwindRecords=sum(len(s['data'])//8 for s in pdatas),
                originalEntryPointPreserved=True,originalCfgEntriesPreserved=True,
                newCfgCallbacks=cfg_callbacks,cfgTableRVA=cfg_rva,installed=False,hardwareTested=False)
    (ROOT/f'build/{kind}-build.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in {'symbols','external','relocations'}},indent=2))
if __name__=='__main__':build(sys.argv[1] if len(sys.argv)>1 else 'backend')
