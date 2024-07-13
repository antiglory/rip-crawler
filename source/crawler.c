#include "include/headers/crawler.h"

// global vars
int32_t error_c = 0x0;

static void segfault_handler() {
    puts("----------------------------SEGFAULT------------------------------");
    puts("exiting");

    exit(1);
}

static void input(const char i_stp[], void* i_vts, input_t i_type) {
    printf("%s", i_stp);

    switch (i_type) {
        case STRING:
            scanf("%s", (char*)i_vts);
            break;
        case INTEGER:
            scanf("%d", (int*)i_vts);
            break;
        case POINTER:
            scanf("%p", (void**)i_vts);
            break;
        case UNSIGNED_LONG:
            scanf("%lx", (unsigned long*)i_vts);
            break;
        case PID:
            scanf("%d", (signed int*)i_vts);
            break;
        default:
            printf("[CRIT] unknown input type, exiting\n");
            exit(EXIT_FAILURE);
    }
}

static void phl(void) {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

    int32_t terminal_width = w.ws_col;

    for (int i = 0; i < terminal_width; ++i)
        putchar('-');

    putchar('\n');
}

static void getps(void) {
    system("ps -aux");

    phl();

    return;
}

static void cprintf(const char* cp_stp, ...) {
    va_list cp_args;
    va_start(cp_args, cp_stp);
    
    for (int c = 0; cp_stp[c] != '\0'; c++) {
        if (cp_stp[c] == '*')
            printf("\033[1;33m*\033[0m");
        else if (cp_stp[c] == '+')
            printf("\033[1;36m+\033[0m");
        else if (cp_stp[c] == '~')
            printf("\033[1;35m~\033[0m");
        else if (cp_stp[c] == '!')
            printf("\033[1;31m!\033[0m");
        else if (cp_stp[c] == 'R') {
            if (cp_stp[c-1] == '[' && cp_stp[c+1] == ']')
                printf("\033[0;32mR\033[0m");
            else
                putchar('R');
        } else if (cp_stp[c] == '%') {
            if (cp_stp[c+1] == 'z') {
                if (cp_stp[c+2] == 'u') {
                    size_t cp_val = va_arg(cp_args, size_t);

                    printf("%zu", cp_val);

                    c += 2;
                } else if (cp_stp[c+2] == 'd') {
                    ssize_t cp_val = va_arg(cp_args, ssize_t);

                    printf("%zd", cp_val);

                    c += 2;
                } else
                    putchar('%');
            } else if (cp_stp[c+1] == 'p') {
                void* cp_val = va_arg(cp_args, void*);

                printf("\033[0;32m%p\033[0m", cp_val);

                c += 1;
            } else if (cp_stp[c+1] == 'l') {
                c += 1;

                if (cp_stp[c+1] == 'x') {
                    unsigned long int* cp_val = va_arg(cp_args, void*);

                    printf("\033[0;32m%lx\033[0m", cp_val);

                    c += 1;
                }
            } else
                putchar('%');
        } else
            putchar(cp_stp[c]);
    }
    
    va_end(cp_args);
}

static size_t gssize(pid_t pid, ulong64_t start_address) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE* maps_file = fopen(maps_path, "r");

    if (!maps_file) {
        error_c = GSSIZE_ERROR_NO_MAPPINGS;

        cprintf("[!] cant get target process mappings to calc the section's size\n\0");
        return 0x0;
    }

    char line[256];
    ulong64_t start, end;
    size_t size = 0x0;

    while (fgets(line, sizeof(line), maps_file)) {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (start == start_address) {
                size = end - start;
                break;
            }
        }
    }

    fclose(maps_file);

    if (size == 0) {
        error_c = GSSIZE_ERROR_NO_SIZE;

        cprintf("[!] could not find a valid section starting at address <%lx>\n\0", start_address);
        return 1;
    }

    return size;
}

static void* salloc(size_t size) {
    void* new_section = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (new_section == MAP_FAILED) {
        error_c = SALLOC_ERROR_MAP_FAILED;

        cprintf("[!] cannot map a new section to attach target process section");
        return NULL;
    }

    return new_section;
}

// is address valid? (sanity check)
static int32_t iav(void* address, void* anon, size_t size) {
    return (address >= anon && address < (anon + size));
}

static void self_dump(void* anon) {
    pid_t self_pid = getpid();
    uint32_t d_size = 1; // dump/disas

    char d_cmd[512];

    input("dump size (decimal): ", &d_size, 'i');

    sprintf(d_cmd, "gdb -batch --pid %d -ex 'x/%di %p' -ex 'quit'", self_pid, d_size, anon);
    system(d_cmd);
    
    printf("(if you see so many (bad) flags, you are probably disassembling the wrong section)\n");

    return;
}

static void crawl(pid_t pid, unsigned long start_address) {
    signal(SIGSEGV, segfault_handler);

    size_t size = gssize(pid, start_address);
    if (size == 0x0)
        return;

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int32_t mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd == -1) exit(EXIT_FAILURE);

    void* anon = salloc(size);

    if (lseek(mem_fd, start_address, SEEK_SET) == -1) {
        close(mem_fd);

        error_c = CRAWL_ERROR_LSEEK;

        cprintf("[!] cannot seek start address\n\0");
        return;
    }

    ssize_t bytes_read = read(mem_fd, anon, size);

    if (bytes_read == -1) {
        close(mem_fd);

        error_c = CRAWL_ERROR_NO_MAPPINGS;

        cprintf("[!] no mappings found\n\0");
        return;
    } 

    else if ((size_t)bytes_read != size)
        cprintf("[*] expected to read '%zu' bytes but only read '%zd' bytes\n", size, bytes_read);

    close(mem_fd);

    size_t page_size = sysconf(_SC_PAGESIZE);
    void* page_start = (void*)((size_t)anon & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        error_c = CRAWL_ERROR_PERM_CHANGE;

        cprintf("[!] cannot change section permissions\n\0");
        return;
    }

    cprintf("[+] successfully crawled to <%p> and self attached in <%p>\n\0", (void*)start_address, anon);

    char response = 0x0;
    void* address = NULL;

    input("do you wanna disas the process? ", &response, 's');

    if (response == 'y')
        self_dump(anon);
    else if (response != 'n' && response != 'y')
        printf("undefined behavior, proceeding\n");

    while (1) {
        input("which address? ", &address, 'p');

        phl();

        // sanity checks
        if (address == NULL || address == 0x0) {
            cprintf("[!] null address, try again\n\n\0");

            continue;
        }

        if (!iav(address, anon, size)) {
            cprintf("[!] invalid address\n\0");
            cprintf("[*] valid range: <%p> to <%p>\n\n\0", anon, anon + size - 1);

            continue;
        }

        break;
    }

    if (*(int*)address == (int)0xc3) {
        cprintf("[*] the provided address is an explicit or a direct RET instruction\n\0");

        goto trunk;
    }

    // pseudo jmp
    ((void(*)())address)();

    cprintf("[R] returned to caller\n\0");

    if (munmap(anon, size) == -1) {
        error_c = CRAWL_ERROR_MUNMAP;

        cprintf("[!] cannot detach crawled section\n\0");
        return;
    } else
        cprintf("[+] successfully detached <%p> from self\n\0", anon);

trunk:

    cprintf("[*] flow has been trunk, nothing else to do\n\0");
    cprintf("[~] exiting\n\0");

    exit(EXIT_SUCCESS);
}

static void vmmap(pid_t pid) {
    char map_file[64];
    snprintf(map_file, sizeof(map_file), "/proc/%d/maps", pid);
    
    FILE* file = fopen(map_file, "r");

    if (file == NULL)
        exit(EXIT_FAILURE);

    phl();
    printf("LEGEND: START | END | PERM | SIZE | OFFSET | FILE\n");

    char line[256];

    while (fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }
    
    fclose(file);

    phl();

    return;
}

static int32_t setup(void) {
    FILE* fp = popen("which gdb", "r");

    char gdb_path[1035];

    if (!(fgets(gdb_path, sizeof(gdb_path)-1, fp)))
        return SANITY_ERROR_GDB_NOT_FOUND;

    pclose(fp);
}

int main(void) {
    setup();

    ulong64_t start_address = 0x0;
    pid_t pid = 0x0;

    getps();

    input("pid: ", &pid, 'o');

    vmmap(pid);

    input("start address: ", &start_address, 'u');

    crawl(pid, start_address);

    return 0;
}