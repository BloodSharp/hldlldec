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

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef int32_t     i32;
typedef uint32_t    u32;

void PE_dos_fwrite(FILE *fd) {
    IMAGE_DOS_HEADER hdr;
    static const u8 dosdata[0x101] =
        "\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x54\x68"
        "\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f"
        "\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20"
        "\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a\x24\x00\x00\x00\x00\x00\x00\x00"
        "\xdb\xd6\xcc\x61\x9f\xb7\xa2\x32\x9f\xb7\xa2\x32\x9f\xb7\xa2\x32"
        "\xe4\xab\xae\x32\x97\xb7\xa2\x32\xf0\xa8\xa9\x32\x90\xb7\xa2\x32"
        "\x1c\xab\xac\x32\xae\xb7\xa2\x32\xf0\xa8\xa8\x32\x31\xb7\xa2\x32"
        "\xc0\x95\xa8\x32\x9e\xb7\xa2\x32\x65\x93\xbb\x32\x9d\xb7\xa2\x32"
        "\xc0\x95\xa9\x32\xb1\xb7\xa2\x32\x18\xab\xa0\x32\xb9\xb7\xa2\x32"
        "\x70\x95\x92\x32\x9e\xb7\xa2\x32\x9f\xb7\xa3\x32\x6c\xb7\xa2\x32"
        "\xfd\xa8\xb1\x32\x8e\xb7\xa2\x32\xe1\x95\xbe\x32\x9c\xb7\xa2\x32"
        "\xac\x95\x87\x32\x9b\xb7\xa2\x32\xcb\x94\x93\x32\xab\xb7\xa2\x32"
        "\xcb\x94\x92\x32\xf2\xb7\xa2\x32\x58\xb1\xa4\x32\x9e\xb7\xa2\x32"
        "\x9f\xb7\xa2\x32\x80\xb7\xa2\x32\x60\x97\xa6\x32\x8c\xb7\xa2\x32"
        "\x52\x69\x63\x68\x9f\xb7\xa2\x32\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    memset(&hdr, 0, sizeof(hdr));
    hdr.e_magic     = IMAGE_DOS_SIGNATURE;
    hdr.e_cblp      = 0x0090;
    hdr.e_cp        = 0x0003;
    hdr.e_cparhdr   = 0x0004;
    hdr.e_maxalloc  = 0xffff;
    hdr.e_sp        = 0x00b8;
    hdr.e_lfarlc    = 0x0040;
    hdr.e_lfanew    = sizeof(hdr) + sizeof(dosdata);
    fwrite(&hdr,     sizeof(hdr),     1, fd);
    fwrite(&dosdata, sizeof(dosdata), 1, fd);
}

void PE_sign_fwrite(FILE *fd) {
    u32         hdr;

    hdr = IMAGE_NT_SIGNATURE;
    fwrite(&hdr,     sizeof(hdr),     1, fd);
}

void PE_file_fwrite(FILE *fd, u32 sections, u32 Characteristics) {
    IMAGE_FILE_HEADER  hdr;

    memset(&hdr, 0, sizeof(hdr));
    hdr.Machine                 = IMAGE_FILE_MACHINE_I386;
    hdr.NumberOfSections        = sections;
    hdr.TimeDateStamp           = time(NULL);
    hdr.SizeOfOptionalHeader    = sizeof(IMAGE_OPTIONAL_HEADER);
    hdr.Characteristics         = Characteristics;
    fwrite(&hdr,     sizeof(hdr),     1, fd);
}