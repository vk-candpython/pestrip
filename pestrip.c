//=================================\\
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 11.06.2026
//     PROJECT  : PE-STRIPPER
//     PLATFORM : WINDOWS
//=================================\\




#define ZERO          0    // Zero out of data
#define MIN_PE_SZ     1024 // 1 KB: Min size for strip PE
#define COFF_STR_BASE 4    // Min offset for string table data


/* Aligns an integer value upward
   to the nearest power-of-two boundary */
#define ALIGN_UP(val, alg) \
    ( ((val) + ((alg) - 1)) & ~((alg) - 1) )


/* Centralized error message string constants */
#define ERR_OS(nm)     "[-] Win32Error: " #nm "() failed"
#define ERR_MIN_SZ     "[!] file size is below minimum PE threshold"
#define ERR_IS_PE      "[-] file is not valid PE binary"
#define ERR_PE_ST      "[-] invalid PE-file structure"
#define ERR_ARCH(n)    "[-] PE-file architecture is not " #n




/* String utilities, Windows utilities
   and PE structures */
#include <string.h>
#include <windows.h>




/* Represents a protected memory segment boundary */
typedef struct {  SIZE_T start, end;  } Region_t;




/* In-place insertion sort to order tracked regions
   by their starting offsets */
static inline VOID sort_regs(Region_t *arr, SIZE_T sz) {
    for (SIZE_T i = 1;  i < sz;  ++i) {
        Region_t k = arr[i]; // Store the current region to be inserted
        SIZE_T  j = i;       // Initialize the shift tracking index


        while (j && (arr[j - 1].start > k.start))
            // Shift larger elements forward to make room
            (arr[j] = arr[j - 1]), j--;

        arr[j] = k; // Place the region into its sorted position
    }
}




/* Converts a base-10 string
   into an unsigned integer */
static inline DWORD parse_dec(LPCSTR p) {
    DWORD r = 0; // Accumulated numeric result


    /* Loop through valid decimal ASCII characters */
    while ((*p >= '0') && (*p <= '9'))
        // Shift radix and inject converted digit
        r = (r * 10) + (*p++ - '0');


    return r;
}




/* Writes an error message to stderr
   and terminates the program */
static VOID cerr(LPCSTR s) {
    if (s) {
        HANDLE h = GetStdHandle(STD_ERROR_HANDLE); // Get standard error handle
        DWORD  n;                                  // Bytes written counter

        if (h != INVALID_HANDLE_VALUE) {
            WriteFile(h, s,    (DWORD)strlen(s), &n, NULL); // Put string
            WriteFile(h, "\n", 1,                &n, NULL); // Put new line
        }
    }


    /* Terminate process immediately */
    ExitProcess(1);
}




/* Extracts the real section name,
   resolving COFF string table offsets
   for long names (e.g. /4) */
static inline VOID get_section_name(
    SIZE_T fsz,
    PIMAGE_SECTION_HEADER sect, LPVOID map,
    PIMAGE_FILE_HEADER hdFl,
    PCHAR out, SIZE_T ln
) {
    /* Zero out buffer and decrement length
       to reserve null-terminator */
    memset(out, ZERO, ln--);



    /* Inline section name (<= 8 bytes) */
    if (sect->Name[0] != '/') {
        memcpy(out, sect->Name, IMAGE_SIZEOF_SHORT_NAME);
        return;
    }



    /* Extract raw byte offset
       from the slash-encoded string */
    DWORD offs = parse_dec((PCHAR)sect->Name + 1);

    /* COFF string table required */
    if (!hdFl->PointerToSymbolTable || (offs < COFF_STR_BASE))
        return;


    /* Calculate string table file offset */
    SIZE_T strtab = (SIZE_T)hdFl->PointerToSymbolTable + (
                    (SIZE_T)hdFl->NumberOfSymbols * IMAGE_SIZEOF_SYMBOL);

    /* Validate string table location */
    if ((strtab > fsz) || (offs > (fsz - strtab)))
        return;


    /* Calculate validated string
       entry offset inside the file */
    SIZE_T stroff = strtab + offs;

    /* Validate extracted string boundary */
    if ((stroff + ln) > fsz)
        return;


    /* Extract long section name
       from the COFF string table */
    memcpy(out, (PCHAR)map + stroff, ln);
}




int main(int argc, char *argv[]) {
    if (argc != 2) cerr(
        "(U) pestrip.exe <PE32+-file>\n"
        "(C) Vladislav Khudash, 2026.\n"
        "(I) Extreme PE-file metadata stripper.\n"
        "(P) GitHub: https://github.com/vk-candpython/pestrip\n"
        "(!) Warning: Modifies target file in-place."
    ); // Enforce correct CLI usage and display tool metadata


/*-----------------------------------------------------------------------------*/


    /* Phase 0: File initialization, validation,
       and memory mapping for direct binary manipulation */
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        cerr(ERR_OS(CreateFileA));


    SIZE_T fsz = 0; // Total size of the input file image



    /* Retrieve target file metadata 
       and perform basic size validation */
    { LARGE_INTEGER st;
    if (!GetFileSizeEx(hFile, &st))
        cerr(ERR_OS(GetFileSizeEx));


    /* Enforce minimum valid size 
       threshold for PE binaries */
    if (st.QuadPart < MIN_PE_SZ)
        cerr(ERR_MIN_SZ);


    /* Set validated target file size */
    fsz = (SIZE_T)st.QuadPart; }



    /* Map the target binary into the process address space
       for direct mutation */
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMap) cerr(ERR_OS(CreateFileMappingA));


    /* Map a view of the file mapping
       into the process address space */
    LPVOID map = MapViewOfFile(hMap, FILE_MAP_READ|FILE_MAP_WRITE, 0, 0, fsz);
    if (!map) cerr(ERR_OS(MapViewOfFile));



    /* Cast mapped memory pointer
       to base DOS header structure */
    PIMAGE_DOS_HEADER hdDos = (PIMAGE_DOS_HEADER)map;


    /* Verify DOS magic signature ("MZ") */
    if (hdDos->e_magic != IMAGE_DOS_SIGNATURE)
        cerr(ERR_IS_PE);


    /* Guard against overlapping NT headers and DOS header */
    else if (hdDos->e_lfanew < sizeof(IMAGE_DOS_HEADER))
        cerr(ERR_PE_ST);


    /* Guard against malformed e_lfanew
       pointer overflowing file boundary */
    else if (((SIZE_T)hdDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) > fsz)
        cerr(ERR_PE_ST);



    /* Advance to the NT headers offset */
    PIMAGE_NT_HEADERS64 hdNt = (PIMAGE_NT_HEADERS64)((PCHAR)map + hdDos->e_lfanew);


    /* Verify PE file signature ("PE\0\0") */
    if (hdNt->Signature != IMAGE_NT_SIGNATURE)
        cerr(ERR_IS_PE);


    /* Enforce strict 64-bit architecture (PE32+ magic validation) */
    else if (hdNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        cerr(ERR_ARCH(x64));


    /* Localize reference to the COFF File Header */
    PIMAGE_FILE_HEADER hdFl = &hdNt->FileHeader;

    /* Localize reference to the 64-bit Optional Header */
    PIMAGE_OPTIONAL_HEADER64 hdOpt = &hdNt->OptionalHeader;


    /* Structural and alignment integrity guard */
    if (
!hdOpt->SizeOfImage      || // Missing virtual image size
!hdOpt->FileAlignment    || // Missing file alignment value
!hdOpt->SectionAlignment || // Missing section alignment value

(hdOpt->FileAlignment    & (hdOpt->FileAlignment    - 1)) || // File alignment is not a power of two
(hdOpt->SectionAlignment & (hdOpt->SectionAlignment - 1)) || // Section alignment is not a power of two

(hdOpt->SectionAlignment < hdOpt->FileAlignment         ) || // Section alignment must be >= file alignment
(hdOpt->ImageBase        & (hdOpt->SectionAlignment - 1)) || // ImageBase must be aligned to section boundary
(hdOpt->SizeOfHeaders    > fsz                          )    // Headers exceed physical file size
    ) cerr(ERR_PE_ST);



    /* Phase 1: Header metadata wipe (
           DOS Header,
           File Header,
           Optional Headers,
           Data Directories
       ) */

    { SIZE_T dosz = sizeof(IMAGE_DOS_HEADER), // Base DOS header size threshold
             dsof = (SIZE_T)hdDos->e_lfanew;  // Raw offset to the 64-bit NT headers


    /* 1. Wipe obsolete DOS fields
       between e_magic and e_lfanew */
    memset(
        (PBYTE)&hdDos->e_magic + sizeof(hdDos->e_magic),
        ZERO,
        dosz - (sizeof(hdDos->e_magic) + sizeof(hdDos->e_lfanew))
    );


    /* 2. Wipe the entire DOS stub area
       between headers first */
    if (dsof > dosz) {
        /* Monolithic NT headers and section table size calculation */
        SIZE_T blk = (
            ((PCHAR)hdOpt - (PCHAR)hdNt) + hdFl->SizeOfOptionalHeader // Size of NT headers up to sections
        ) + (
            hdFl->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)     // Total size of all section headers
        );

        /* Validate NT headers and section table
           stay within physical file boundaries */
        if ((blk > fsz) || (dsof > (fsz - blk)))
            cerr(ERR_PE_ST);


        /* Shift NT headers downward to overwrite the DOS stub */
        memmove((PBYTE)map + dosz, (PBYTE)map + dsof, blk);


        /* Rebind NT headers offset */
        hdDos->e_lfanew = (LONG)dosz;
        hdNt = (PIMAGE_NT_HEADERS64)((PCHAR)map + dosz);

        /* Update internal structures to the new address */
        hdFl  = &hdNt->FileHeader;
        hdOpt = &hdNt->OptionalHeader;

        /* Calculate unaligned size of new header block */
        SIZE_T nwhd_sz = dosz + blk;

        /* Write the final aligned size of headers */
        hdOpt->SizeOfHeaders = ALIGN_UP((DWORD)nwhd_sz, hdOpt->FileAlignment);


        /* Zero out padding after sections up to aligned size */
        if (hdOpt->SizeOfHeaders > nwhd_sz)
            memset((PBYTE)map + nwhd_sz, ZERO, hdOpt->SizeOfHeaders - nwhd_sz);

        /*
        Note:
            Trailing garbage left
            at the old NT headers location (dsof)
            will be cleanly wiped
            during interval processing in Phase 4.2
        */
    } }



    /* Phase 1.5: Sanitize Optional Header fields */

    /* [A] Linker metadata */
    hdOpt->MajorLinkerVersion = ZERO; // Wipe compiler major version
    hdOpt->MinorLinkerVersion = ZERO; // Wipe compiler minor version


    /* [B] Stats – never read by loader */
    hdOpt->SizeOfCode              = ZERO; // Raw size of text section
    hdOpt->SizeOfInitializedData   = ZERO; // Raw size of data section
    hdOpt->SizeOfUninitializedData = ZERO; // Raw size of BSS section
    hdOpt->BaseOfCode              = ZERO; // RVA of .text, ignored in PE32+ (64-bit)


    /* [C] Version stamps – purely informational */
    hdOpt->MajorOperatingSystemVersion = ZERO; // Legacy OS major version
    hdOpt->MinorOperatingSystemVersion = ZERO; // Legacy OS minor version
    hdOpt->MajorImageVersion           = ZERO; // User-defined major version
    hdOpt->MinorImageVersion           = ZERO; // User-defined minor version
    hdOpt->Win32VersionValue           = ZERO; // Abandoned Win32 reserved field


    /* [D] Checksum & Legacy flags */
    hdOpt->CheckSum    = ZERO; // Ignored for user‑mode EXE/DLL
    hdOpt->LoaderFlags = ZERO; // Obsolete debugger break flags



    /* Phase 1.8: Wipe non-essential data directory entries */

    /* Bulk wipe non-essential data directories */
    { PIMAGE_DATA_DIRECTORY dd = hdOpt->DataDirectory;


    const DWORD dirs[] = {
        IMAGE_DIRECTORY_ENTRY_DEBUG,        // Telemetry & PDB path metadata
        IMAGE_DIRECTORY_ENTRY_SECURITY,     // Digital signature metadata
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR,    // Dead IA-64/MIPS register slot
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, // Unused chip‑specific field
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  // Deprecated pre-ASLR optimization
    };


    for (BYTE i = 0;  i < (sizeof(dirs) / sizeof(dirs[0]));  i++) {
        DWORD idx = dirs[i]; // Get directory index

        /* Guard against Out-Of-Bounds (OOB) access
           if PE has a truncated DataDirectory array */
        if (idx < hdOpt->NumberOfRvaAndSizes) {
            dd[idx].Size           = ZERO; // Clear entry size
            dd[idx].VirtualAddress = ZERO; // Clear entry offset
        }
    } }



    /* Phase 3: Sanitize Section Headers and Data */

    /* Allocate an internal tracking table
       for protected memory regions */
    SIZE_T rgcn = 1,                                                  // Initial protected region count (PE header)
           rgsz = (rgcn + hdFl->NumberOfSections) * sizeof(Region_t); // Buffer size for region tracking table


    /* Obtain handle to the process default heap */
    HANDLE hPheap = GetProcessHeap();
    if (!hPheap) cerr(ERR_OS(GetProcessHeap));


    /* Allocate memory using Windows Heap API */
    Region_t *regs = (Region_t*)HeapAlloc(hPheap, HEAP_ZERO_MEMORY, rgsz);
    if (!regs) cerr(ERR_OS(HeapAlloc));



    /* Active program headers counter */
    { WORD aphnm = 0;

    /* Get pointer to the first section header */
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(hdNt);

    /* Next packed physical file offset tracker */
    DWORD nx_raw_offs = hdOpt->SizeOfHeaders;


    regs[0].start = 0;                    // Anchor at absolute file start (DOS & NT Headers)
    regs[0].end   = hdOpt->SizeOfHeaders; // Protect everything up to the first physical section



    /* Temporary buffer for section name resolution */
    { CHAR s_nm[IMAGE_SIZEOF_SHORT_NAME << 1];

    /* Filter, sanitize and repack
       surviving section headers */
    for (WORD i = 0;  i < hdFl->NumberOfSections;  i++) {
        /* Resolve real name */
        get_section_name(
            fsz,
            &sect[i], map,
            hdFl,
            s_nm, sizeof(s_nm)
        );



        /* 0. Filter out non-essential metadata,
           compiler telemetry, and legacy debug
           sections from the PE binary layout */

        /* Heuristic: drop explicit linker garbage */
        if (sect[i].Characteristics & (IMAGE_SCN_LNK_REMOVE |
                                       IMAGE_SCN_LNK_INFO))
            continue;


        /* Fallback: catch unflagged debug/telemetry */
        else if (
        /* GCC / MinGW / Clang artifacts */
            !strcmp( s_nm, ".comment" ) || // Compiler telemetry
            !strcmp( s_nm, ".ident"   ) || // Compiler version identification
            !strncmp(s_nm, ".debug", 6) || // DWARF debug symbols (.debug_info, etc.)
            !strcmp( s_nm, ".symtab"  ) || // MinGW symbol table
            !strcmp( s_nm, ".strtab"  ) || // MinGW string table
            !strcmp( s_nm, ".shstrtab") || // MinGW section headers string table

        /* MSVC (Visual Studio) & Linker artifacts */
            !strcmp( s_nm, ".drectve" ) || // Leaked linker directives
            !strcmp( s_nm, ".msvcjmc" )    // MSVC "Just My Code" debugging info
        ) continue;



        /* Shift valid section header downward
           to compact the table
           and overwrite space left
           by deleted junk sections */
        if (i != aphnm)
            memcpy(&sect[aphnm], &sect[i], sizeof(IMAGE_SECTION_HEADER));



        /* 1. Wipe obsolete COFF legacy fields */
        memset(sect[aphnm].Name, ZERO, IMAGE_SIZEOF_SHORT_NAME); // Zero out section name


        sect[aphnm].PointerToRelocations = ZERO; // Clear section-specific static relocation offset
        sect[aphnm].PointerToLinenumbers = ZERO; // Remove legacy COFF source-code line numbers pointer
        sect[aphnm].NumberOfRelocations  = ZERO; // Zero out the legacy section relocation counter
        sect[aphnm].NumberOfLinenumbers  = ZERO; // Zero out the legacy source-line entries counter


        /* Enforce PE spec: zero raw pointer
           if section is empty on disk */
        if (!sect[aphnm].SizeOfRawData)
            sect[aphnm].PointerToRawData = ZERO;



        /* 2. Extract physical section layout boundaries */
        SIZE_T p_filesz = sect[aphnm].SizeOfRawData,    // Initial section size on disk
               p_offset = sect[aphnm].PointerToRawData; // Section offset inside file


        /* Skip virtual-only sections
           (e.g. .bss without raw data) */
        if (!p_filesz) {
            if (p_offset) cerr(ERR_PE_ST); // Virtual-only section must not have raw file offset

            aphnm++; // Preserve section header despite missing file payload
            continue;
        }


        /* Absolute end offset of the section */
        SIZE_T p_end = p_filesz + p_offset;


        /* Validate physical section boundaries
           and enforce monotonic file layout */
        if (
            (p_end    < p_offset   ) || // Integer overflow in (offset + size)
            (p_end    > fsz        ) || // Section extends beyond physical file boundary
            (p_offset < nx_raw_offs)    // Physical section order violation / overlap
        ) cerr(ERR_PE_ST);



        /* Get section tail memory pointer */
        PBYTE seg_tail = (PBYTE)map + p_end;
  
        /* Rewind past trailing zeros */
        while (p_filesz && !*(seg_tail - 1)) {
            p_filesz--; // Shrink file footprint
            seg_tail--; // Move tail backward
        }

        /* Re-align the trimmed size */
        p_filesz = ALIGN_UP(p_filesz, (SIZE_T)hdOpt->FileAlignment);



        /* Update section header metadata
           with the optimized physical size */
        sect[aphnm].SizeOfRawData = (DWORD)p_filesz;

        /* Section payload vanished completely
           after tail-zero trimming */
        if (!p_filesz) {
            sect[aphnm++].PointerToRawData = ZERO;
            continue;
        }


        /* Shift section body left to eliminate physical slack space */
        if (p_offset != nx_raw_offs)
            memmove((PBYTE)map + nx_raw_offs, (PBYTE)map + p_offset, p_filesz);


        /* Bind updated physical file offset to section header */
        sect[aphnm].PointerToRawData = nx_raw_offs;

        /* Recalculate true physical end after alignment */
        p_end = sect[aphnm].PointerToRawData + p_filesz;

        /* Align and advance physical file offset tracker */
        nx_raw_offs = ALIGN_UP(nx_raw_offs + (DWORD)p_filesz, hdOpt->FileAlignment);



        /* 3. Track preserved section body region */
        regs[rgcn].start = sect[aphnm].PointerToRawData; // Save optimized physical start offset
        regs[rgcn].end   = p_end;                        // Save calculated true physical end offset


        /* Advance region tracker
           and active headers counter */
        rgcn++; aphnm++;
    } }

    /* Validate rebuilt file layout boundary */
    if (nx_raw_offs > fsz) cerr(ERR_PE_ST);



    /* Wipe old duplicate headers left in the tail
       of the array after compaction */
    for (WORD i = aphnm;  i < hdFl->NumberOfSections;  i++)
        memset(&sect[i], ZERO, sizeof(IMAGE_SECTION_HEADER));



    /* Update COFF headers and wipe metadata */
    hdFl->NumberOfSections     = aphnm; // Set optimized section count
    hdFl->TimeDateStamp        = ZERO;  // Compilation timestamp
    hdFl->PointerToSymbolTable = ZERO;  // COFF symbol table offset
    hdFl->NumberOfSymbols      = ZERO;  // Number of COFF symbols



    /* Recalculate virtual image size in memory
       after section trimming */
    DWORD mxva  = 0; // High water mark for virtual address space
    for (WORD i = 0;  i < aphnm;  i++) {

        DWORD va = sect[i].VirtualAddress,   // RVA where the section is mapped
              vs = sect[i].Misc.VirtualSize; // Unaligned in-memory section size

        /* Detect integer overflow in RVA end calculation */
        if ((va + vs) < va) cerr(ERR_PE_ST);


        /* Calculate absolute virtual
           end of the current active section */
        DWORD cur = va + vs;

        /* Track image high-water mark
           for final SizeOfImage rebuild */
        if (cur > mxva) mxva = cur;
    }



    /* Bind aligned virtual size
       to the PE optional header */
    if (mxva) hdOpt->SizeOfImage = ALIGN_UP(mxva, hdOpt->SectionAlignment);
    else cerr(ERR_PE_ST); }



    /* Sort tracked memory regions sequentially 
       by their starting offsets 
       to prepare for the interval merging phase */
    sort_regs(regs, rgcn);



    /* Phase 4: Collapse overlapping
       or adjacent protected memory regions */

    /* 1. Collapse sorted tracking table intervals 
       to eliminate duplicates */
    SIZE_T mrcn   = 0; // Index of the current merged region
    for (SIZE_T i = 1;  i < rgcn;  ++i) {


    /* Non-contiguous region detected, push next */
        if (regs[i].start > regs[mrcn].end)
            regs[++mrcn]  = regs[i];

    /* Overlap found, expand current upper bound */
        else if (regs[i].end > regs[mrcn].end)
            regs[mrcn].end   = regs[i].end;


    } mrcn++; // Fix count of collapsed active regions



    /* 2. Wipe out unmapped alignment 
       slack space between sections */
    { SIZE_T pos  = regs[0].end; // Start right after cleared PE headers region
    for (SIZE_T i = 1;  i < mrcn;  i++) {


        /* Zero out padding between sections 
           without violating raw data boundaries */
        if (regs[i].start > pos) 
            memset((PBYTE)map + pos, ZERO, regs[i].start - pos);


        /* Advance cursor to the end
           of current section */
        if (regs[i].end > pos)
            pos = regs[i].end;
    } }



    /* Phase 5: Commit modified pages to storage
       and perform aggressive physical truncation */
    SIZE_T ltsg = regs[mrcn - 1].end; // End of last active region

    /* Align to 8-byte boundary */
    SIZE_T nwfsz = ALIGN_UP(ltsg, (SIZE_T)8); // New file size
    if (nwfsz > fsz) nwfsz = fsz;             // Never expand the original file size


    /* Clear alignment padding */
    if (nwfsz > ltsg)
        memset((PBYTE)map + ltsg, ZERO, nwfsz - ltsg);



    /* Phase 6: Commit changes, unmap structures,
       and truncate file physically */

    /* Flush modified pages to disk */
    if (!FlushViewOfFile(map, 0))
        cerr(ERR_OS(FlushViewOfFile));


    UnmapViewOfFile(map); // Detach file view from process memory
    CloseHandle(   hMap); // Close mapping object handle


    /* Physically truncate the file
       to discard all omitted trailing data (overlay) */
    { LARGE_INTEGER li; li.QuadPart = nwfsz;

    /* Move file pointer to the new end position */
    if (!SetFilePointerEx(hFile, li, NULL, FILE_BEGIN))
        cerr(ERR_OS(SetFilePointerEx));

    /* Truncate the file at current pointer */
    else if (!SetEndOfFile(hFile))
        cerr(ERR_OS(SetEndOfFile)); }


    /* Close target file descriptor backing store */
    CloseHandle(hFile);

    /* Free region tracking table memory from heap */
    HeapFree(hPheap, 0, regs);



    /* Calculate compression stats */
    SIZE_T pct = ((UINT64)(fsz - nwfsz) * 1000) / fsz;


    /* Format the compression statistics string */
    CHAR s_buf[128];
    INT  s_len = wsprintfA(
        s_buf, "[+] Stripped: %I64u -> %I64u bytes (-%I64u.%I64u%%)\n",
        (UINT64)fsz,
        (UINT64)nwfsz,
        (UINT64)(pct / 10),
        (UINT64)(pct % 10)
    );


    /* Write final statistics to stderr */
    DWORD _n; WriteFile(GetStdHandle(STD_ERROR_HANDLE),
        s_buf, (DWORD)s_len, &_n, NULL);
    /* Example: [+] Stripped: 46872 -> 12288 bytes (-73.7%) */



    /* Return success to stripped target file */
    return 0;
}
