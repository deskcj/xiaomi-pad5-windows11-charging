/* User-mode ARM64 test only. Maps bytes as non-executable data, never loads or
 * executes the driver. Exercises the OS unwinder on emulated boundary contexts.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_all(const char *path, size_t *size) {
    FILE *file = NULL;
    unsigned char *data;
    long length;
    if (fopen_s(&file, path, "rb") || !file) return NULL;
    if (fseek(file, 0, SEEK_END) || (length=ftell(file))<=0 || fseek(file,0,SEEK_SET)) {fclose(file);return NULL;}
    *size=(size_t)length;
    data=(unsigned char *)malloc(*size);
    if (!data || fread(data,1,*size,file)!=*size) {free(data);fclose(file);return NULL;}
    fclose(file);return data;
}

int main(int argc, char **argv) {
    size_t file_size, fixture_size, pos=8;
    unsigned char *file, *fixture, *image, *stack;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sections;
    IMAGE_DATA_DIRECTORY exception_dir;
    PRUNTIME_FUNCTION table;
    unsigned int i, j, count, failures=0;
    if (argc!=3) {fprintf(stderr,"usage: native_unwind.exe candidate.sys unwind-fixtures.bin\n");return 2;}
    file=read_all(argv[1],&file_size);fixture=read_all(argv[2],&fixture_size);
    if (!file || !fixture || file_size<4096 || fixture_size<8) return 3;
    dos=(IMAGE_DOS_HEADER *)file;
    if (dos->e_magic!=IMAGE_DOS_SIGNATURE || dos->e_lfanew<0 || (size_t)dos->e_lfanew+sizeof(*nt)>file_size) return 4;
    nt=(IMAGE_NT_HEADERS64 *)(file+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_ARM64) return 5;
    image=(unsigned char *)VirtualAlloc(NULL,nt->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    stack=(unsigned char *)VirtualAlloc(NULL,0x2000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!image || !stack) return 6;
    memcpy(image,file,nt->OptionalHeader.SizeOfHeaders);
    sections=IMAGE_FIRST_SECTION(nt);
    for(i=0;i<nt->FileHeader.NumberOfSections;i++) {
        if((size_t)sections[i].PointerToRawData+sections[i].SizeOfRawData>file_size || sections[i].VirtualAddress+sections[i].SizeOfRawData>nt->OptionalHeader.SizeOfImage) return 7;
        memcpy(image+sections[i].VirtualAddress,file+sections[i].PointerToRawData,sections[i].SizeOfRawData);
    }
    if(*(unsigned int *)fixture!=0x3157444e) return 8;
    count=*(unsigned int *)(fixture+4);
    if(fixture_size != 8+(size_t)count*(8+31*8+0x2000)) return 9;
    exception_dir=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    table=(PRUNTIME_FUNCTION)(image+exception_dir.VirtualAddress);
    for(i=0;i<count;i++) {
        unsigned int pc=*(unsigned int *)(fixture+pos), sp=*(unsigned int *)(fixture+pos+4);
        CONTEXT context;
        DWORD64 establisher=0;
        PVOID handler_data=NULL;
        PRUNTIME_FUNCTION entry=NULL;
        int bad=0;
        ZeroMemory(&context,sizeof(context));
        if(sp>=0x2000) return 10;
        memcpy(context.X,fixture+pos+8,31*8);
        memcpy(stack,fixture+pos+8+31*8,0x2000);
        context.ContextFlags=CONTEXT_FULL;
        context.Pc=(DWORD64)image+pc;
        context.Sp=(DWORD64)stack+sp;
        for(j=0;j<exception_dir.Size/sizeof(RUNTIME_FUNCTION);j++) {
            if(table[j].BeginAddress>pc) break;
            entry=&table[j];
        }
        if(!entry) return 11;
        __try {
            RtlVirtualUnwind(UNW_FLAG_NHANDLER,(DWORD64)image,context.Pc,entry,&context,&handler_data,&establisher,NULL);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            bad=1;
        }
        if(context.Pc!=0x400000 || context.Sp!=(DWORD64)stack+0x1000 || context.Fp!=0xabc1234567890000ui64) bad=1;
        for(j=19;j<=28;j++) if(context.X[j] != 0xabc0000000000000ui64+(j-19)) bad=1;
        if(bad) {failures++;printf("failure fixture=%u rva=0x%x resultingPc=0x%llx spOffset=0x%llx\n",i,pc,context.Pc,context.Sp-(DWORD64)stack);}
        pos+=8+31*8+0x2000;
    }
    printf("{\"nativeARM64UnwindCases\":%u,\"failures\":%u,\"kernelDriverLoaded\":false,\"mappedDriverMemoryExecutable\":false}\n",count,failures);
    VirtualFree(image,0,MEM_RELEASE);VirtualFree(stack,0,MEM_RELEASE);free(file);free(fixture);
    return failures?1:0;
}
