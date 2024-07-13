#ifndef CRAWLER_H
#define CRAWLER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <execinfo.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>

#define CRAWL_ERROR_MUNMAP         0x32
#define CRAWL_ERROR_LSEEK          0x33
#define CRAWL_ERROR_NO_MAPPINGS    0x34
#define CRAWL_ERROR_PERM_CHANGE    0x35

#define GSSIZE_ERROR_NO_SIZE       0x50
#define GSSIZE_ERROR_NO_MAPPINGS   0x51

#define SALLOC_ERROR_MAP_FAILED    0x77

#define SANITY_ERROR_GDB_NOT_FOUND 0x40

typedef enum {
    STRING = 's',
    INTEGER = 'i',
    CHARACTER = 'c',
    POINTER = 'p',
    UNSIGNED_LONG = 'u',
    PID = 'o'
} input_t;

typedef unsigned long ulong64_t;
typedef char          byte_t;

#endif