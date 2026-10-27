/* Native user-mode ARM64 unwind validation. SYS is PAGE_READWRITE data,
 * never executable and never passed to a driver/service loader. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_all(const char *path, size_t *size) {
    FILE *f = NULL;
    unsigned char *bytes;
    long length;
    if (fopen_s(&f, path, "rb") || !f) return NULL;
    if (fseek(f, 0, SEEK_END) || (length = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET)) { fclose(f); return NULL; }
    *size = (size_t)length;
    bytes = (unsigned char *)malloc(*size);
    if (!bytes || fread(bytes, 1, *size, f) != *size) { free(bytes); fclose(f); return NULL; }
    fclose(f);
    return bytes;
}

static DWORD64 translate(DWORD64 value, unsigned char *image, DWORD image_size, unsigned char *stack) {
    if (value >= 0x140000000ui64 && value < 0x140000000ui64 + image_size)
        return (DWORD64)image + value - 0x140000000ui64;
    if (value >= 0x207000ui64 && value < 0x209000ui64)
        return (DWORD64)stack + value - 0x207000ui64;
    return value;
}

static PRUNTIME_FUNCTION lookup(unsigned char *image, IMAGE_DATA_DIRECTORY directory, DWORD pc) {
    PRUNTIME_FUNCTION table = (PRUNTIME_FUNCTION)(image + directory.VirtualAddress);
    DWORD i;
    for (i = 0; i < directory.Size / sizeof(RUNTIME_FUNCTION); i++) {
        DWORD length;
        if (table[i].BeginAddress > pc) break;
        if (table[i].UnwindData & 3)
            length = ((table[i].UnwindData >> 2) & 0x7FF) * 4;
        else
            length = (*(DWORD *)(image + table[i].UnwindData) & 0x3FFFF) * 4;
        if (pc < table[i].BeginAddress + length) return &table[i];
    }
    return NULL;
}

int main(int argc, char **argv) {
    size_t file_size, fixture_size, pos = 8;
    unsigned char *file, *fixture, *image, *stack;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sections;
    IMAGE_DATA_DIRECTORY directory;
    DWORD i, j, count, failures = 0, leaf_steps = 0, os_steps = 0;
    if (argc != 3) return 2;
    file = read_all(argv[1], &file_size);
    fixture = read_all(argv[2], &fixture_size);
    if (!file || !fixture || file_size < 4096 || fixture_size < 8) return 3;
    dos = (IMAGE_DOS_HEADER *)file;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 || (size_t)dos->e_lfanew + sizeof(*nt) > file_size) return 4;
    nt = (IMAGE_NT_HEADERS64 *)(file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64) return 5;
    image = (unsigned char *)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    stack = (unsigned char *)VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!image || !stack) return 6;
    memcpy(image, file, nt->OptionalHeader.SizeOfHeaders);
    sections = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if ((size_t)sections[i].PointerToRawData + sections[i].SizeOfRawData > file_size || sections[i].VirtualAddress + sections[i].SizeOfRawData > nt->OptionalHeader.SizeOfImage) return 7;
        memcpy(image + sections[i].VirtualAddress, file + sections[i].PointerToRawData, sections[i].SizeOfRawData);
    }
    if (*(DWORD *)fixture != 0x3157444E) return 8;
    count = *(DWORD *)(fixture + 4);
    if (fixture_size != 8 + (size_t)count * (8 + 31 * 8 + 0x2000)) return 9;
    directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    for (i = 0; i < count; i++) {
        DWORD pc = *(DWORD *)(fixture + pos), sp = *(DWORD *)(fixture + pos + 4);
        CONTEXT context;
        int bad = 0;
        DWORD depth = 0;
        ZeroMemory(&context, sizeof(context));
        if (sp >= 0x2000) return 10;
        memcpy(context.X, fixture + pos + 8, 31 * 8);
        memcpy(stack, fixture + pos + 8 + 31 * 8, 0x2000);
        context.ContextFlags = CONTEXT_FULL;
        context.Pc = (DWORD64)image + pc;
        context.Sp = (DWORD64)stack + sp;
        for (j = 0; j < 31; j++) context.X[j] = translate(context.X[j], image, nt->OptionalHeader.SizeOfImage, stack);
        for (j = 0; j < 0x2000; j += 8) {
            DWORD64 *word = (DWORD64 *)(stack + j);
            *word = translate(*word, image, nt->OptionalHeader.SizeOfImage, stack);
        }
        __try {
            while (context.Pc != 0x400000 && depth++ < 8) {
                DWORD rva;
                DWORD64 establisher = 0;
                PVOID handler_data = NULL;
                PRUNTIME_FUNCTION entry;
                if (context.Pc < (DWORD64)image || context.Pc >= (DWORD64)image + nt->OptionalHeader.SizeOfImage) { bad = 1; break; }
                rva = (DWORD)(context.Pc - (DWORD64)image);
                entry = lookup(image, directory, rva);
                if (!entry) {
                    /* The ONLY omitted entries are the verified arithmetic
                     * leaves with no stack/memory/nonvolatile operations. */
                    if (rva < 0x14000 || rva >= 0x14070) { bad = 1; break; }
                    context.Pc = context.Lr;
                    leaf_steps++;
                } else {
                    RtlVirtualUnwind(UNW_FLAG_NHANDLER, (DWORD64)image, context.Pc, entry, &context, &handler_data, &establisher, NULL);
                    os_steps++;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { bad = 1; }
        if (context.Pc != 0x400000 || context.Sp != (DWORD64)stack + 0x1000 || context.Fp != 0xABC1234567890000ui64) bad = 1;
        for (j = 19; j <= 28; j++) if (context.X[j] != 0xABC0000000000000ui64 + j - 19) bad = 1;
        if (bad) { failures++; printf("failure fixture=%lu rva=0x%lx pc=0x%llx sp=0x%llx\n", i, pc, context.Pc, context.Sp - (DWORD64)stack); }
        pos += 8 + 31 * 8 + 0x2000;
    }
    printf("{\"nativeARM64UnwindCases\":%lu,\"failures\":%lu,\"leafUnwindSteps\":%lu,\"osRtlVirtualUnwindSteps\":%lu,\"kernelDriverLoaded\":false,\"mappedDriverMemoryExecutable\":false}\n", count, failures, leaf_steps, os_steps);
    VirtualFree(image, 0, MEM_RELEASE);
    VirtualFree(stack, 0, MEM_RELEASE);
    free(file);
    free(fixture);
    return failures ? 1 : 0;
}
