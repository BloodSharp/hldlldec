/*
    Copyright 2007,2008 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#include "hldlldec_pe.h"

#define VER         "0.2"
#define DEFALIGN    4096
#define DEFCHARACT  (IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE)

void halflife_dll_decrypt(u8 *out_file, u8 *data, u32 datasz);
void find_impexp_tables(u8 *base, u32 baseoff, u32 imagebase, u32 *impoff, u32 *impsz, u32 *expoff, u32 *expsz, u32 *iatoff, u32 *iatsz);
u8 *fd_read(u8 *name, int *fdlen);
void checkoverwrite(u8 *name);
void std_err(void);

typedef struct {
    u32    unknown;
    u32    Sections;
    u32    copywhat;
    u32    ImageBase;
    u32    EntryPoint;
    u32    ImportTable;
} hlhdr_t;

typedef struct {
    u32    rva;
    u32    rva_size;
    u32    file_size;
    u32    file_offset;
    u32    reloc_addr;  // I guess
} hlsec_t;

typedef struct {
    u8      *Name;
    u32     Characteristics;
} fixed_sections_t;

fixed_sections_t fixed_sections[] = {
    { (u8*)".text",  IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ },
    { (u8*)".rdata", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
    { (u8*)".data",  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
    { (u8*)".rsrc",  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ },
    { NULL,     0 }
};

int main(int argc, char *argv[]) {
    u32     filelen;
    u8      *filebuff,
            *in_file,
            *out_file;

    fputs("\n"
        "Half-life DLL decrypter and rebuilder " VER "\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

    if(argc < 3) {
        printf("\n"
            "Usage: %s <input.DLL> <output.DLL>\n"
            "\n"
            "some examples of scrambled DLLs are sw.dll, hw.dll and some client.dll\n"
            "\n", argv[0]);
        exit(1);
    }

    in_file  = (u8*)argv[1];
    out_file = (u8*)argv[2];

    filebuff = fd_read(in_file, (int*)&filelen);

    halflife_dll_decrypt(out_file, filebuff, filelen);

    printf("- the DLL has been decrypted and rebuilt\n");
    free(filebuff);
    return(0);
}

void show_hl_info(u8* base, hlhdr_t* hlhdr, hlsec_t* hlsec) {
    int     i;

    printf("\n"
        "  unknown         %08x\n"
        "  Sections         %08x\n"
        "  copywhat         %08x\n"
        "  ImageBase        %08x\n"
        "  EntryPoint       %08x\n"
        "  ImportTable      %08x\n",
        hlhdr->unknown,
        hlhdr->Sections,
        hlhdr->copywhat,
        hlhdr->ImageBase,
        hlhdr->EntryPoint,
        hlhdr->ImportTable);

    for (i = 0; i < hlhdr->Sections; i++) {
        printf("\n"
            "- section %u\n"
            "  rva_size         %08x\n"
            "  file_size        %08x\n"
            "  file_offset      %08x\n"
            "  rva              %08x\n"
            "  reloc_addr       %08x\n",
            i,
            hlsec[i].rva_size,
            hlsec[i].file_size,
            hlsec[i].file_offset,
            hlsec[i].rva,
            hlsec[i].reloc_addr);
    }

    printf("\n");
}

u32 myalign(u32 num) {
    return((num + (DEFALIGN - 1)) & (~(DEFALIGN - 1)));
}

void fdalign(FILE* fd, int size) {
    int     len;
    u8      buff[DEFALIGN];

    memset(buff, 0, sizeof(buff));

    size = myalign(size) - size;
    for (len = sizeof(buff); size > 0; size -= len) {
        if (len > size) len = size;
        fwrite(buff, len, 1, fd);
    }
}

void halflife_dll_decrypt(u8* out_file, u8* data, u32 datasz) {
    IMAGE_SECTION_HEADER    section;
    IMAGE_OPTIONAL_HEADER          optional;
    hlhdr_t* hlhdr;
    hlsec_t* hlsec;
    FILE* fd;
    u32     i,
        tmp,
        section_offset,
        import_rva,
        import_size,
        export_rva,
        export_size,
        iat_rva,
        iat_size;
    u8      chr;

    if (*(u32*)(data + 64) != 0x12345678) {
        printf("\nAlert: this DLL doesn't seem encrypted with the Valve algorithm!\n");
    }

    data += 68;   // all zeroes
    datasz -= 68;
    chr = 'W';
    for (i = 0; i < datasz; i++) {
        data[i] ^= chr;
        chr += data[i] + 'W';
    }
    hlhdr = (hlhdr_t*)(void*)data;
    hlsec = (hlsec_t*)(void*)(data + sizeof(hlhdr_t));
    data -= 68;   // restore
    datasz += 68;

    hlhdr->copywhat ^= 0x7a32bc85;
    hlhdr->ImageBase ^= 0x49c042d1;
    hlhdr->ImportTable ^= 0x872c3d47;
    hlhdr->EntryPoint -= 12;
    hlhdr->Sections++;

    show_hl_info(data, hlhdr, hlsec);

    /* when all the section have been placed in memory         */
    /* HL.EXE calls hlhdr->EntryPoint and then hlhdr->copywhat */
    /* copying a zone of the DLL in the HL.EXE process         */

    memset(&optional, 0, sizeof(optional));
    optional.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    optional.MajorLinkerVersion = 6;
    optional.MinorLinkerVersion = 0;
    //optional.SizeOfCode                  = ;
    //optional.SizeOfInitializedData       = ;
    //optional.SizeOfUninitializedData     = ;
    optional.AddressOfEntryPoint = hlhdr->EntryPoint - hlhdr->ImageBase;
    optional.BaseOfCode = hlsec[0].rva - hlhdr->ImageBase; // .text
    optional.BaseOfData = hlsec[1].rva - hlhdr->ImageBase; // .rdata
    optional.ImageBase = hlhdr->ImageBase;
    optional.SectionAlignment = DEFALIGN;
    optional.FileAlignment = DEFALIGN;
    optional.MajorOperatingSystemVersion = 4;
    optional.MinorOperatingSystemVersion = 0;
    optional.MajorImageVersion = 0;
    optional.MinorImageVersion = 0;
    optional.MajorSubsystemVersion = 4;
    optional.MinorSubsystemVersion = 0;
    optional.Win32VersionValue = 0;
    //optional.SizeOfImage                 = ;
    optional.SizeOfHeaders = DEFALIGN;    // it's ever less than the default alignment
    optional.CheckSum = 0;
    optional.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    optional.DllCharacteristics = 0;
    optional.SizeOfStackReserve = DEFALIGN * 256;
    optional.SizeOfStackCommit = DEFALIGN;
    optional.SizeOfHeapReserve = DEFALIGN * 256;
    optional.SizeOfHeapCommit = DEFALIGN;
    optional.LoaderFlags = 0;
    optional.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    for (i = 0; i < hlhdr->Sections; i++) {
        tmp = (i < 4) ? fixed_sections[i].Characteristics : DEFCHARACT;
        optional.SizeOfImage += myalign(hlsec[i].rva_size);
        if (tmp & IMAGE_SCN_CNT_CODE)                optional.SizeOfCode += myalign(hlsec[i].rva_size);
        if (tmp & IMAGE_SCN_CNT_INITIALIZED_DATA)    optional.SizeOfInitializedData += myalign(hlsec[i].rva_size);
        if (tmp & IMAGE_SCN_CNT_UNINITIALIZED_DATA)  optional.SizeOfUninitializedData += myalign(hlsec[i].rva_size);
    }
    optional.SizeOfImage += optional.SizeOfHeaders;

    printf("- search offsets and sizes of the import and export tables\n");

    import_rva = hlhdr->ImportTable;
    find_impexp_tables(
        data + hlsec[1].file_offset,
        hlsec[1].rva,
        hlhdr->ImageBase,
        &import_rva, &import_size,
        &export_rva, &export_size,
        &iat_rva, &iat_size);

    optional.DataDirectory[0].VirtualAddress = export_rva - hlhdr->ImageBase;
    optional.DataDirectory[0].Size = export_size;
    optional.DataDirectory[1].VirtualAddress = import_rva - hlhdr->ImageBase;
    optional.DataDirectory[1].Size = import_size;
    if (hlhdr->Sections > 3) {
        optional.DataDirectory[2].VirtualAddress = hlsec[3].rva - hlhdr->ImageBase;
        optional.DataDirectory[2].Size = hlsec[3].rva_size;
    }
    optional.DataDirectory[12].VirtualAddress = iat_rva - hlhdr->ImageBase;
    optional.DataDirectory[12].Size = iat_size;

    printf("- now I build the DLL\n\n");

    checkoverwrite(out_file);
    fd = fopen((const char*)out_file, "wb");
    if (!fd) std_err();

    PE_dos_fwrite(fd);
    PE_sign_fwrite(fd);
    PE_file_fwrite(fd, hlhdr->Sections, IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL);
    fwrite(&optional, sizeof(optional), 1, fd);

    section_offset = optional.SizeOfHeaders;
    for (i = 0; i < hlhdr->Sections; i++) {
        memset(&section, 0, sizeof(section));
        if (i < 4) {
            strncpy((char*)section.Name, (const char*)fixed_sections[i].Name, IMAGE_SIZEOF_SHORT_NAME);
        }
        else {
            snprintf((char*)section.Name, IMAGE_SIZEOF_SHORT_NAME, "sec%u", i);
        }
        section.Misc.VirtualSize = hlsec[i].rva_size;
        section.VirtualAddress = hlsec[i].rva - hlhdr->ImageBase;
        section.SizeOfRawData = myalign(hlsec[i].file_size);
        section.PointerToRawData = section_offset;
        section.PointerToRelocations = hlsec[i].reloc_addr;
        section.Characteristics = (i < 4) ? fixed_sections[i].Characteristics : DEFCHARACT;
        fwrite(&section, sizeof(section), 1, fd);
        section_offset += myalign(hlsec[i].file_size);
    }

    fseek(fd, optional.SizeOfHeaders, SEEK_SET);
    for (i = 0; i < hlhdr->Sections; i++) {
        printf("- place section %d at offset %08x\n", i, (u32)ftell(fd));
        if ((hlsec[i].file_offset + hlsec[i].file_size) > datasz) {
            printf("- Alert: the section %d is bigger than the original file (%u %d)\n", i, (hlsec[i].file_offset + hlsec[i].file_size), datasz);
            fwrite(data + hlsec[i].file_offset, datasz - hlsec[i].file_offset, 1, fd);
            fseek(fd, (hlsec[i].file_offset + hlsec[i].file_size) - datasz, SEEK_CUR);
        }
        else {
            fwrite(data + hlsec[i].file_offset, hlsec[i].file_size, 1, fd);
        }
        fdalign(fd, hlsec[i].file_size);
    }

    fclose(fd);
}

// experimental method for calculating the size of import and export table, specific for these half-life dll but could work in other cases too
void find_impexp_tables(u8* base, u32 baseoff, u32 imagebase, u32* impoff, u32* impsz, u32* expoff, u32* expsz, u32* iatoff, u32* iatsz) {
    IMAGE_IMPORT_DESCRIPTOR* iid;
    IMAGE_THUNK_DATA* itd;
    IMAGE_EXPORT_DIRECTORY* ied;
    u32     off,
        maxiat,
        maxoff;
    int     i;
    u8* p;

    *iatoff = 0xffffffff;
    maxiat = 0;

    maxoff = 0;
    for (iid = (IMAGE_IMPORT_DESCRIPTOR*)(base + (*impoff - baseoff)); iid->Name; iid++) {
        if (iid->Name > maxoff) maxoff = iid->Name;
        if (iid->FirstThunk < *iatoff) *iatoff = iid->FirstThunk;

        for (itd = (IMAGE_THUNK_DATA*)(base + iid->FirstThunk - (baseoff - imagebase)); itd->u1.AddressOfData; itd++) {
            off = (((u8*)(itd + 1) - base) + (baseoff - imagebase)) + 4;
            if (off > maxiat) maxiat = off;

            if (itd->u1.Function & IMAGE_ORDINAL_FLAG32) {
                //printf("  IMPORT %04x\n", itd->u1.Function & 0xffff);
            }
            else {
                off = itd->u1.Function + 2;
                if (off > maxoff) maxoff = off;
                //printf("  IMPORT %s\n", base + off - (baseoff - imagebase));
            }
        }
    }
    iid++;
    *impsz = (u8*)iid - (base + (*impoff - baseoff));

    *iatsz = maxiat - *iatoff;
    *iatoff += imagebase;

    for (p = base + maxoff - (baseoff - imagebase); *p; p++);
    for (p++; !*p; p++);     // we get the timestamp value of the export directory
    p -= (p - base) & 3;    // simple check of the alignment, enough
    p -= 4;                 // skip the characteristics for finding the export table
    *expoff = (p - base) + baseoff;

    ied = (IMAGE_EXPORT_DIRECTORY*)p;
    for (itd = (IMAGE_THUNK_DATA*)(base + ied->AddressOfNames - (baseoff - imagebase)), i = 0; i < ied->NumberOfNames; itd++, i++) {
        if (itd->u1.Function & IMAGE_ORDINAL_FLAG32) {
            //printf("  EXPORT %04x\n", itd->u1.Function & 0xffff);
        }
        else {
            off = itd->u1.Function;
            if (off > maxoff) maxoff = off;
            //printf("  EXPORT %s\n", base + off - (baseoff - imagebase));
        }
    }

    for (p = base + maxoff - (baseoff - imagebase); *p; p++);
    for (p++; (p - base) & 3; p++);  // alignment is not needed, but I prefer it
    *expsz = ((p - base) + baseoff) - *expoff;

    printf("- import table found: %08x of %u bytes\n", *impoff - baseoff, *impsz);
    printf("- export table found: %08x of %u bytes\n", *expoff - baseoff, *expsz);
    printf("- IAT    table found: %08x of %u bytes\n", *iatoff - baseoff, *iatsz);
}

u8* fd_read(u8* name, int* fdlen) {
    struct stat xstat;
    FILE* fd;
    u8* buff;

    printf("- open file %s\n", name);
    fd = fopen((char*)name, "rb");
    if (!fd) std_err();
    fstat(_fileno(fd), &xstat);
    buff = (u8*)malloc(xstat.st_size);
    fread(buff, xstat.st_size, 1, fd);
    fclose(fd);
    *fdlen = xstat.st_size;
    return(buff);
}

void checkoverwrite(u8* name) {
    FILE* fd;

    printf("- create file %s\n", name);
    fd = fopen((char*)name, "rb");
    if (fd) {
        fclose(fd);
        printf("- file already exists, do you want to overwrite it (y/N)? ");
        fflush(stdin);
        if (tolower(fgetc(stdin)) != 'y') exit(1);
    }
}

void std_err(void) {
    perror("\nError");
    exit(1);
}