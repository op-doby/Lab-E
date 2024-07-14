#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILES 2

int debug_mode = 0;
int fd[MAX_FILES] = {-1, -1};
void *map_start[MAX_FILES] = {NULL, NULL};

void toggle_debug_mode() {
    debug_mode = !debug_mode;
    printf("Debug mode %s\n", debug_mode ? "on" : "off");
}

void examine_elf_file() {
    char filename[256];
    printf("Enter ELF file name: ");
    scanf("%255s", filename);
    int i;
    for (i = 0; i < MAX_FILES; i++) {
        if (fd[i] == -1) 
            break;
    }
    if (i == MAX_FILES) {
        printf("Maximum number of open files reached.\n");
        return;
    }
    fd[i] = open(filename, O_RDONLY);
    if (fd[i] < 0) {
        perror("ERROR: cannot open file");
        return;
    }
    off_t file_size = lseek(fd[i], 0, SEEK_END);
    map_start[i] = mmap(0, file_size, PROT_READ, MAP_PRIVATE, fd[i], 0);
    if (map_start[i] == MAP_FAILED) {
        perror("ERROR: mmap failed");
        close(fd[i]);
        fd[i] = -1;
        return;
    }
    Elf32_Ehdr *header = (Elf32_Ehdr *) map_start[i];
    if (header->e_ident[EI_MAG0] != ELFMAG0 || header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 || header->e_ident[EI_MAG3] != ELFMAG3) {
        printf("ERROR: Not an ELF file.\n");
        munmap(map_start[i], file_size);
        close(fd[i]);
        fd[i] = -1;
        return;
    }
    printf("Magic: %c%c%c\n", header->e_ident[EI_MAG1], header->e_ident[EI_MAG2], header->e_ident[EI_MAG3]);
    printf("Data encoding: %d\n", header->e_ident[EI_DATA]);
    printf("Entry point: 0x%x\n", header->e_entry);
    printf("Section header offset: %d\n", header->e_shoff);
    printf("Number of section headers: %d\n", header->e_shnum);
    printf("Size of each section header: %d\n", header->e_shentsize);
    printf("Program header offset: %d\n", header->e_phoff);
    printf("Number of program headers: %d\n", header->e_phnum);
    printf("Size of each program header: %d\n", header->e_phentsize);

    if (debug_mode) {
        printf("Debug: Mapped file %s, size %ld\n", filename, file_size);
    }
}

void print_section_names() {
    for (int i = 0; i < MAX_FILES; i++) {
        if (fd[i] == -1) continue;

        Elf32_Ehdr *header = (Elf32_Ehdr *) map_start[i];
        Elf32_Shdr *sh_table = (Elf32_Shdr *)(map_start[i] + header->e_shoff);
        char *sh_strtab = (char *)(map_start[i] + sh_table[header->e_shstrndx].sh_offset);

        printf("File %d: %s\n", i + 1, sh_strtab);
        for (int j = 0; j < header->e_shnum; j++) {
            printf("[%2d] %s 0x%08x 0x%08x 0x%08x %u\n",
                j,
                &sh_strtab[sh_table[j].sh_name],
                sh_table[j].sh_addr,
                sh_table[j].sh_offset,
                sh_table[j].sh_size,
                sh_table[j].sh_type);
        }
    }
}

void print_symbols() {
    for (int i = 0; i < MAX_FILES; i++) {
        if (fd[i] == -1) continue;

        Elf32_Ehdr *header = (Elf32_Ehdr *) map_start[i];
        Elf32_Shdr *sh_table = (Elf32_Shdr *)(map_start[i] + header->e_shoff);
        char *sh_strtab = (char *)(map_start[i] + sh_table[header->e_shstrndx].sh_offset);

        int symtab_idx = -1;
        for (int j = 0; j < header->e_shnum; j++) {
            if (sh_table[j].sh_type == SHT_SYMTAB) {
                symtab_idx = j;
                break;
            }
        }

        if (symtab_idx == -1) {
            printf("No symbol table found in file %d\n", i + 1);
            continue;
        }

        Elf32_Sym *symtab = (Elf32_Sym *)(map_start[i] + sh_table[symtab_idx].sh_offset);
        char *strtab = (char *)(map_start[i] + sh_table[sh_table[symtab_idx].sh_link].sh_offset);
        int sym_count = sh_table[symtab_idx].sh_size / sh_table[symtab_idx].sh_entsize;

        for (int j = 1; j < sym_count; j++) {
            Elf32_Sym *sym = &symtab[j];
            printf("[%2d] 0x%08x %2d %s %s\n",
                j,
                sym->st_value,
                sym->st_shndx,
                sym->st_shndx < header->e_shnum ? &sh_strtab[sh_table[sym->st_shndx].sh_name] : "ABS",
                &strtab[sym->st_name]);
        }
    }
}

void check_files_for_merge() {
    if (fd[0] == -1 || fd[1] == -1) {
        printf("Exactly two ELF files are required for merge\n");
        return;
    }

    Elf32_Ehdr *header1 = (Elf32_Ehdr *) map_start[0];
    Elf32_Ehdr *header2 = (Elf32_Ehdr *) map_start[1];
    Elf32_Shdr *sh_table1 = (Elf32_Shdr *)(map_start[0] + header1->e_shoff);
    Elf32_Shdr *sh_table2 = (Elf32_Shdr *)(map_start[1] + header2->e_shoff);

    int symtab_idx1 = -1, symtab_idx2 = -1;
    for (int j = 0; j < header1->e_shnum; j++) {
        if (sh_table1[j].sh_type == SHT_SYMTAB) {
            symtab_idx1 = j;
            break;
        }
    }
    for (int j = 0; j < header2->e_shnum; j++) {
        if (sh_table2[j].sh_type == SHT_SYMTAB) {
            symtab_idx2 = j;
            break;
        }
    }

    if (symtab_idx1 == -1 || symtab_idx2 == -1) {
        printf("One or both files do not contain a symbol table\n");
        return;
    }

    Elf32_Sym *symtab1 = (Elf32_Sym *)(map_start[0] + sh_table1[symtab_idx1].sh_offset);
    Elf32_Sym *symtab2 = (Elf32_Sym *)(map_start[1] + sh_table2[symtab_idx2].sh_offset);
    char *strtab1 = (char *)(map_start[0] + sh_table1[sh_table1[symtab_idx1].sh_link].sh_offset);
    char *strtab2 = (char *)(map_start[1] + sh_table2[sh_table2[symtab_idx2].sh_link].sh_offset);

    int sym_count1 = sh_table1[symtab_idx1].sh_size / sh_table1[symtab_idx1].sh_entsize;
    int sym_count2 = sh_table2[symtab_idx2].sh_size / sh_table2[symtab_idx2].sh_entsize;

    for (int j = 1; j < sym_count1; j++) {
        Elf32_Sym *sym1 = &symtab1[j];
        for (int k = 1; k < sym_count2; k++) {
            Elf32_Sym *sym2 = &symtab2[k];
            if (strcmp(&strtab1[sym1->st_name], &strtab2[sym2->st_name]) == 0) {
                printf("Symbol %s found in both files\n", &strtab1[sym1->st_name]);
            }
        }
    }
}

void merge_elf_files() {
    printf("Not implemented yet.\n");
}

void quit() {
    for (int i = 0; i < MAX_FILES; i++) {
        if (fd[i] != -1) {
            munmap(map_start[i], lseek(fd[i], 0, SEEK_END));
            close(fd[i]);
        }
    }
    exit(0);
}

struct menu_option {
    char *name;
    void (*func)();
};

struct menu_option menu[] = {
    {"Toggle Debug Mode", toggle_debug_mode},
    {"Examine ELF File", examine_elf_file},
    {"Print Section Names", print_section_names},
    {"Print Symbols", print_symbols},
    {"Check Files for Merge", check_files_for_merge},
    {"Merge ELF Files", merge_elf_files},
    {"Quit", quit}
};

int main() {
    int choice;
    while (1) {
        printf("Choose action:\n");
        for (int i = 0; i < sizeof(menu)/sizeof(menu[0]); i++) {
            printf("%d-%s\n", i, menu[i].name);
        }
        scanf("%d", &choice);
        if (choice >= 0 && choice < sizeof(menu)/sizeof(menu[0])) {
            menu[choice].func();
        } else {
            printf("Invalid choice\n");
        }
    }
    return 0;
}
