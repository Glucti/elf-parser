#include "elf_parse.h"
#include <sys/stat.h>
#include <ctype.h> 

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

int open_elf(const char *path, ElfFile *elf) {
    int fd = open(path, O_RDONLY | O_SYNC);
    if (fd < 0) return -1;
    
    struct stat st;
    if (fstat(fd, &st) == -1) {
        handle_error("fstat");
    }

    elf->size = st.st_size;
    elf->map = mmap(NULL, elf->size, PROT_READ, MAP_PRIVATE, fd, (off_t)0);
    close(fd);

    if (elf->map == MAP_FAILED) return -1;
    elf->eh = (Elf64_Ehdr *)elf->map;
    return 0;
}

int close_elf(ElfFile *elf) {
    if (elf->map && elf->map != MAP_FAILED) {
        munmap(elf->map, elf->size);
    }
}

int is_elf(ElfFile *elf) {
    return strncmp((char *)elf->eh->e_ident, "\x7F""ELF", 4) == 0;
}

void print_info(ElfFile *elf_file) {

    Elf64_Ehdr *eh = elf_file->eh;
    switch(eh->e_type) {
        case ET_NONE:
            printf("Unknown type (0x00)\n");
            break;
        case ET_REL:
            printf("A relocatable file\n");
            break;
        case ET_EXEC:
            printf("An Executable File\n");
            break;
        case ET_DYN:
            printf("A shared object\n");
            break;
        case ET_CORE:
            printf("A core file\n");
            break;
    };

    // print entry
    printf("File entry:\t");
    printf("0x%08lx\n", eh->e_entry);

    // print offset
    printf("Start (offset):\t");
    printf("0x%08lx\n", eh->e_phoff);
    printf("Number of entries:\t");
    printf("%d entries\n", eh->e_phnum);
    printf("%d bytes\n", eh->e_phentsize);
}

const char *pt_type(uint32_t t) {
    switch (t) {
        case PT_NULL:    return "NULL";
        case PT_LOAD:    return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP:  return "INTERP";
        case PT_NOTE:    return "NOTE";
        case PT_PHDR:    return "PHDR";
        case PT_TLS:     return "TLS";
        default:         return "UNKNOWN";
    }
}


void prog_header_dump(ElfFile *elf_file) {
    Elf64_Ehdr *eh = elf_file->eh;
    Elf64_Phdr *ph = (Elf64_Phdr *) ((char *)eh + eh->e_phoff);

    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr *seg = &ph[i];
        printf("Segment %d: type=%s offset=0x%lx vaddr=0x%lx filesz=0x%lx memsz=0x%lx\n",
           i,
           pt_type(seg->p_type),
           seg->p_offset,
           seg->p_vaddr,
           seg->p_filesz,
           seg->p_memsz);
    }
}

const char *sh_type_str(uint32_t t) {
    switch (t) {
        case SHT_NULL:          return "NULL";
        case SHT_PROGBITS:      return "PROGBITS";
        case SHT_SYMTAB:        return "SYMTAB";
        case SHT_STRTAB:        return "STRTAB";
        case SHT_RELA:          return "RELA";
        case SHT_HASH:          return "HASH";
        case SHT_DYNAMIC:       return "DYNAMIC";
        case SHT_NOTE:          return "NOTE";
        case SHT_NOBITS:        return "NOBITS";
        case SHT_REL:           return "REL";
        case SHT_SHLIB:         return "SHLIB";
        case SHT_DYNSYM:        return "DYNSYM";
        case SHT_INIT_ARRAY:    return "INIT_ARRAY";
        case SHT_FINI_ARRAY:    return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case SHT_GROUP:         return "GROUP";
        case SHT_SYMTAB_SHNDX:  return "SYMTAB_SHNDX";
        default:                return "UNKNOWN";
    }
}

void sec_header_dump(ElfFile *elf_file) {
    Elf64_Ehdr *eh = elf_file->eh;
    Elf64_Shdr *sh = (Elf64_Shdr *) ((char *)eh + eh->e_shoff);

    const char *shstrtab = (char *)elf_file->map + sh[elf_file->eh->e_shstrndx].sh_offset;

    //The Section Header Table is literally an array of Elf64_Shdr structs, sitting at file offset e_shoff.
    // e_shnum tells you how many entries are in the array.
    // Each Elf64_Shdr describes one section (like .text, .data, .bss, .symtab, etc.).

    for (int i = 0; i < elf_file->eh->e_shnum; i++) {
        const char *name = shstrtab + sh[i].sh_name;
        printf("[%2d] %-20s type=0x%x addr=0x%lx offset=0x%lx size=0x%lx\n",
               i,
               name,
               sh_type_str(sh[i].sh_type),
               (unsigned long)sh[i].sh_addr,
               (unsigned long)sh[i].sh_offset,
               (unsigned long)sh[i].sh_size);
    }
}

void dump_section(ElfFile *elf_file, const char* target) {
    Elf64_Ehdr *eh = elf_file->eh;
    Elf64_Shdr *sh = (Elf64_Shdr *) ((char *)eh + eh->e_shoff);

    const char *shstrtab = (char *)elf_file->map + sh[elf_file->eh->e_shstrndx].sh_offset;
    for (int i = 0; i < elf_file->eh->e_shnum; i++) {
        const char *name = shstrtab + sh[i].sh_name;
        if (strcmp(name, target) == 0) {
            unsigned char *sec = (unsigned char *)elf_file->map + sh[i].sh_offset;
            size_t size = sh[i].sh_size;

            printf("\nDump of Section %s ; size %zu: \n", name, size);
            for (size_t j = 0; j < size; j += 16) {
                printf("%08zx  ", j);

                //hex 
                for (size_t k = 0; k < 16; k++) {
                    if (j + k < size)
                        printf("%02x ", sec[j + k]);
                    else
                        printf("   ");
                }

                printf(" ");

                for (size_t k = 0; k < 16 && j + k < size; k++) {
                    unsigned char c = sec[j + k];
                    printf("%c", isprint(c) ? c : '.');
                }
                printf("\n");
            }

        }
    }
}








