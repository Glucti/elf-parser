#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include "elf_parse.h"

void usage(const char *p) {
    printf("Usage %s [options] <elf file>\n", p);
    printf("Options:\n");
    printf(" -i         Print ELF header info\n");
    printf(" -p         Print ELF program header\n");
    printf(" -s         Print ELF file section headers\n");
    printf(" -x <section> Drump specific section\n");
}

int main(int argc, char *argv[]) {
    int opt;
    int info = 0, print_pheader = 0, print_sheader = 0;
    char *target = NULL;


    while ((opt = getopt(argc, argv, "ipsx:")) != -1) {
        switch(opt) {
            case 'i' : info = 1; break;
            case 'p' : print_pheader = 1; break;
            case 's' : print_sheader = 1; break;
            case 'x' : target = optarg; break;
            default: 
                usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    const char *path = argv[optind];
    ElfFile elf;

    if (open_elf(path, &elf) < 0) {
        perror("elf_open");
        return -1;
    }

    if (!is_elf(&elf)) {
        printf("NOT an ELF file\n");
        close_elf(&elf);
        return -1;
    }

    if (info) print_info(&elf);
    if (print_pheader) prog_header_dump(&elf);
    if (print_sheader) sec_header_dump(&elf);
    if (target) dump_section(&elf, target);

    close_elf(&elf);

    return 0;
}



// int main(int argc, char *argv[]) {

//     if (argc < 2) {
//         printf("Usage %s <elf file>\n", argv[0]);
//         return 0;
//     }

//     ElfFile elf;
//     if (open_elf(argv[1], &elf) < 0) {
//         perror("elf_open");
//         return 1;
//     }

//     if (!is_elf(&elf)) {
//         printf("Not an ELF file!\n");
//         close_elf(&elf);
//         return 1;
//     }

//     print_info(&elf);
//     prog_header_dump(&elf);
//     sec_header_dump(&elf);

//     dump_section(&elf, ".data");

//     close_elf(&elf);
//     return 0;

// }