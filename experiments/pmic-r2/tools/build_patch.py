"""Constrained ARM64 COFF linker and reproducible fix20 repair. No installation.
Only accepts the two audited input hashes. Unknown relocations fail closed.
"""
import argparse,hashlib,json,struct,sys
from pathlib import Path
fallback=Path(__file__).resolve().parents[2]/'research/2026-10-26/tools/python-deps'
if fallback.exists():sys.path.insert(0,str(fallback))
import pefile

FIX='9955517922e3a0d13287034616c08f8dbad1322c248954477a144073f5f606d2'
STOCK='533c3a555e111d4b12b657d026c92d63d5170d57297432d03bdaf3be96c7886a'
align=lambda n,a:(n+a-1)//a*a
sha=lambda b:hashlib.sha256(b).hexdigest()
def signed(n,bits):return n-(1<<bits) if n&(1<<(bits-1)) else n
def branch(from_rva,to_rva,link=False):
    delta=to_rva-from_rva
    assert delta%4==0 and -(1<<27)<=delta<(1<<27)
    return (0x94000000 if link else 0x14000000)|((delta//4)&0x3ffffff)

def build(fix_path,stock_path,obj_path,out_path):
    fix=Path(fix_path).read_bytes();stock=Path(stock_path).read_bytes()
    assert sha(fix)==FIX,'Unexpected fix20 input'
    assert sha(stock)==STOCK,'Unexpected stock input'
    pe=pefile.PE(data=fix);sp=pefile.PE(data=stock)
    assert pe.FILE_HEADER.Machine==0xaa64
    assert pe.OPTIONAL_HEADER.SectionAlignment==0x1000 and pe.OPTIONAL_HEADER.FileAlignment==0x200
    raw_end=max(s.PointerToRawData+s.SizeOfRawData for s in pe.sections)
    result=bytearray(fix[:raw_end])
    # Restore data pools and remove abandoned code caves, including the skipped
    # logging block. Other fix20 VCONN/role tweaks remain, explicitly experimental.
    restored=[]
    for start,end in [(0x1348,0x135c),(0x2648,0x26b0),(0xa880,0xa898),(0xadb0,0xadb8)]:
        at=pe.get_offset_from_rva(start)
        result[at:at+end-start]=sp.get_data(start,end-start)
        restored.append([hex(start),hex(end)])

    obj=Path(obj_path).read_bytes()
    machine,nsec,timestamp,symoff,nsym,optsize,flags=struct.unpack_from('<HHIIIHH',obj)
    assert machine==0xaa64 and optsize==0,'Expected ordinary ARM64 COFF object'
    strings=obj[symoff+nsym*18:]
    def name(field):
        if field[:4]==b'\0'*4:
            off=struct.unpack_from('<I',field,4)[0]
            return strings[off:].split(b'\0',1)[0].decode()
        value=field.split(b'\0',1)[0].decode()
        if value.startswith('/') and value[1:].isdigit():return strings[int(value[1:]):].split(b'\0',1)[0].decode()
        return value
    sections=[]
    for i in range(nsec):
        pos=20+40*i;fields=struct.unpack_from('<8sIIIIIIHHI',obj,pos)
        nm,vs,va,size,raw,rel,ln,nrel,nln,chars=fields
        sections.append({'name':name(nm),'data':bytearray(obj[raw:raw+size]),'relocs':[struct.unpack_from('<IIH',obj,rel+10*j) for j in range(nrel)],'index':i+1})
    symbols=[]
    for i in range(nsym):
        nm,value,section,typ,storage,aux=struct.unpack_from('<8sIhHBB',obj,symoff+18*i)
        # Auxiliary entries aren't referenced by accepted relocations.
        try:nm=name(nm)
        except (UnicodeDecodeError,ValueError):nm='<aux>'
        symbols.append({'name':nm,'value':value,'section':section,'type':typ,'storage':storage,'aux':aux})
    texts=[s for s in sections if s['name']=='.text$mn']
    assert len(texts)==1,'Multiple code sections require an explicit placement plan'
    text=texts[0]
    # MSVC can emit a separate .xdata/.pdata pair for every shrink-wrapped
    # fragment. Preserve ALL pairs; taking next(...) silently loses records.
    xdatas=[s for s in sections if s['name']=='.xdata']
    pdatas=[s for s in sections if s['name']=='.pdata']
    assert xdatas and pdatas,'Missing compiler unwind metadata'
    assert all(not s['data'] or s['name'] in {'.text$mn','.xdata','.pdata','.drectve','.debug$S','.debug$T','.chks64'} for s in sections),'Unexpected allocated COFF section'
    code_rva=align(pe.OPTIONAL_HEADER.SizeOfImage,0x1000)
    meta_rva=code_rva+0x1000
    stub_rva=code_rva+align(len(text['data']),4)
    old_pd=pe.get_data(pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress,pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size)
    assert len(old_pd)%8==0 and all(len(s['data'])%8==0 for s in pdatas)
    placements={text['index']:code_rva}
    cursor=meta_rva
    for section in xdatas:
        cursor=align(cursor,4)
        placements[section['index']]=cursor
        cursor+=len(section['data'])
    combined_pd_rva=align(cursor,8)
    cursor=combined_pd_rva+len(old_pd)
    for section in pdatas:
        placements[section['index']]=cursor
        cursor+=len(section['data'])
    external={'__ImageBase':0,'PmicReadByte':0xb858,'PmicMaskedWrite':0xb948,'LegacySetRole':stub_rva}
    reloc_report=[]
    for section in [text]+xdatas+pdatas:
        for off,si,kind in section['relocs']:
            sym=symbols[si]
            if sym['section']>0:
                assert sym['section'] in placements,(sym,kind)
                target=placements[sym['section']]+sym['value']
            elif sym['section']==0:
                assert sym['name'] in external,('Unknown external',sym)
                target=external[sym['name']]
            else:raise AssertionError(('Unsupported symbol section',sym))
            place=placements[section['index']]+off
            word=struct.unpack_from('<I',section['data'],off)[0]
            if kind==2: # IMAGE_REL_ARM64_ADDR32NB
                word=(word+target)&0xffffffff
            elif kind==3: # BRANCH26
                addend=signed(word&0x3ffffff,26)*4
                word=branch(place,target+addend,bool(word&0x80000000))
            elif kind==4: # PAGEBASE_REL21 / ADRP
                imm=signed(((word>>5)&0x7ffff)<<2|((word>>29)&3),21)*4096
                delta=((target+imm)&~4095)-(place&~4095)
                assert delta%4096==0 and -(1<<32)<=delta<(1<<32)
                page=(delta//4096)&0x1fffff
                word=(word&~((0x7ffff<<5)|(3<<29)))|((page&3)<<29)|((page>>2)<<5)
            elif kind==6: # PAGEOFFSET_12A / ADD immediate
                assert ((word>>22)&1)==0
                imm=(word>>10)&0xfff
                word=(word&~(0xfff<<10))|(((target+imm)&0xfff)<<10)
            else:raise AssertionError(('Unsupported relocation',hex(kind),sym))
            struct.pack_into('<I',section['data'],off,word)
            reloc_report.append({'section':section['name'],'offset':hex(off),'kind':kind,'symbol':sym['name'],'target':hex(target)})
    code=text['data']+b'\0'*(stub_rva-code_rva-len(text['data']))
    code+=struct.pack('<II',0x7100103f,branch(stub_rva+4,0x8ac4)) # cmp w1,#4; b legacy body
    assert len(code)<4096
    compiled_pd=b''.join(s['data'] for s in pdatas)
    meta=bytearray(combined_pd_rva-meta_rva)
    for section in xdatas:
        offset=placements[section['index']]-meta_rva
        meta[offset:offset+len(section['data'])]=section['data']
    meta+=old_pd+compiled_pd
    assert len(meta)<4096
    runtime=[struct.unpack_from('<II',old_pd+compiled_pd,i) for i in range(0,len(old_pd)+len(compiled_pd),8)]
    assert [r[0] for r in runtime]==sorted(r[0] for r in runtime),'Unsorted exception table'
    assert len({r[0] for r in runtime})==len(runtime),'Duplicate runtime function start'
    entry=next(s for s in symbols if s['name']=='RepairSetRole')
    hook=code_rva+entry['value']
    struct.pack_into('<I',result,pe.get_offset_from_rva(0x8ac0),branch(0x8ac0,hook))
    section_table=pe.sections[0].get_file_offset()
    assert section_table+40*(len(pe.sections)+2)<=pe.OPTIONAL_HEADER.SizeOfHeaders
    section_manifest=[]
    for idx,(nm,rva,payload,chars) in enumerate([(b'.ncode',code_rva,code,0x60000020),(b'.nmeta',meta_rva,meta,0x40000040)]):
        ptr=align(len(result),0x200);result.extend(b'\0'*(ptr-len(result)))
        rawsize=align(len(payload),0x200)
        result.extend(payload);result.extend(b'\0'*(rawsize-len(payload)))
        sh=struct.pack('<8sIIIIIIHHI',nm.ljust(8,b'\0'),len(payload),rva,rawsize,ptr,0,0,0,0,chars)
        pos=section_table+40*(len(pe.sections)+idx)
        result[pos:pos+40]=sh
        section_manifest.append({'name':nm.decode(),'rva':hex(rva),'virtualSize':len(payload),'rawSize':rawsize,'flags':hex(chars)})
    def opt(name,value):struct.pack_into('<I',result,pe.OPTIONAL_HEADER.get_field_absolute_offset(name),value)
    struct.pack_into('<H',result,pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),len(pe.sections)+2)
    opt('SizeOfImage',align(meta_rva+len(meta),0x1000))
    opt('SizeOfCode',pe.OPTIONAL_HEADER.SizeOfCode+align(len(code),0x200))
    opt('SizeOfInitializedData',pe.OPTIONAL_HEADER.SizeOfInitializedData+align(len(meta),0x200))
    struct.pack_into('<II',result,pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].get_file_offset(),combined_pd_rva,len(old_pd)+len(compiled_pd))
    struct.pack_into('<II',result,pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(),0,0)
    opt('CheckSum',0)
    checked=pefile.PE(data=bytes(result))
    opt('CheckSum',checked.generate_checksum())
    checked=pefile.PE(data=bytes(result))
    assert checked.verify_checksum()
    # Existing imports, load configuration, original exception bytes and relocations remain intact.
    for directory in [1,5,10,12]:
        d=pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory]
        assert checked.get_data(d.VirtualAddress,d.Size)==pe.get_data(d.VirtualAddress,d.Size),directory
    assert checked.get_data(combined_pd_rva,len(old_pd))==old_pd
    assert all(not(s.Characteristics&0x80000000 and s.Characteristics&0x20000000) for s in checked.sections),'RWX section'
    out=Path(out_path);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(result)
    report={'status':'EXPERIMENTAL_NOT_HARDWARE_TESTED','inputFix20SHA256':FIX,'inputStockSHA256':STOCK,'objectSHA256':sha(obj),'outputSHA256':sha(result),'outputBytes':len(result),'hookRVA':hex(hook),'legacyStubRVA':hex(stub_rva),'restoredRanges':restored,'newSections':section_manifest,'compilerRuntimeFunctionRecords':len(compiled_pd)//8,'compilerXdataSections':len(xdatas),'compilerPdataSections':len(pdatas),'allCompilerUnwindSectionsPreserved':True,'exceptionDirectoryRVA':hex(combined_pd_rva),'exceptionDirectorySize':len(old_pd)+len(compiled_pd),'relocations':reloc_report,'newImports':False,'preservesLegacyFix20RoleHeuristic':True,'hardwareInstallPerformed':False}
    out.with_suffix('.build.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='relocations'},indent=2))
    return report

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--fix20',required=True);ap.add_argument('--stock',required=True);ap.add_argument('--object',required=True);ap.add_argument('--output',required=True)
    a=ap.parse_args();build(a.fix20,a.stock,a.object,a.output)
