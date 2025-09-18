#include <elf.h>
#include <stdio.h>
#include <stdlib.h> 
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

typedef struct {
    void *map;
    size_t size;
    Elf64_Ehdr *eh;
} ElfFile;

int open_elf(const char *path, ElfFile *elf);
int close_elf(ElfFile *elf);
int is_elf(ElfFile *eh);
void print_info(ElfFile *elf_file);
void prog_header_dump(ElfFile *elf_file);
void sec_header_dump(ElfFile *elf_file);
void dump_section(ElfFile *elf_file, const char* target);
