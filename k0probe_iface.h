/*
 * k0probe_iface.h  -  Shared kernel/user IOCTL interface for K0Probe driver
 *
 * Include in BOTH the kernel driver (.sys) and the user-mode tool.
 * No kernel headers required here; plain C types only.
 */
#pragma once
#ifndef K0PROBE_IFACE_H
#define K0PROBE_IFACE_H

#include <stdint.h>

/* -- Device name (user-mode opens \\.\K0Probe) --------------------- */
#define K0PROBE_DEVICE_NAME     "\\\\.\\K0Probe"
#define K0PROBE_DEVICE_SYMLINK  L"\\DosDevices\\K0Probe"
#define K0PROBE_DEVICE_NT       L"\\Device\\K0Probe"

/* -- IOCTL codes --------------------------------------------------- */
/*  Method: METHOD_BUFFERED  Access: FILE_ANY_ACCESS  Type: 0x8000 (non-MS) */
#define K0_IOCTL_BASE           0x8000
#define K0_IOCTL(n)             CTL_CODE(K0_IOCTL_BASE, (n), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_K0_READ_MEM       K0_IOCTL(0x801)   /* K0ReadReq  -> raw bytes  */
#define IOCTL_K0_WRITE_MEM      K0_IOCTL(0x802)   /* K0WriteReq -> BOOL       */
#define IOCTL_K0_QUERY_REGIONS  K0_IOCTL(0x803)   /* K0RegionReq -> K0Region[]*/
#define IOCTL_K0_WATCH_ADD      K0_IOCTL(0x804)   /* K0WatchReq -> K0WatchId  */
#define IOCTL_K0_WATCH_REMOVE   K0_IOCTL(0x805)   /* K0WatchId  -> BOOL       */
#define IOCTL_K0_POLL_EVENTS    K0_IOCTL(0x806)   /* empty      -> K0Event[]  */
#define IOCTL_K0_FLUSH_EVENTS   K0_IOCTL(0x807)   /* empty      -> empty      */
#define IOCTL_K0_GET_PHYS_ADDR  K0_IOCTL(0x808)   /* uint64_t VA-> uint64_t PA*/
#define IOCTL_K0_SET_TARGET_PID K0_IOCTL(0x809)   /* uint32_t PID -> BOOL     */
#define IOCTL_K0_GET_CR3        K0_IOCTL(0x80A)   /* empty      -> uint64_t   */

/* -- Structures --------------------------------------------------- */
#pragma pack(push, 1)

/* IOCTL_K0_READ_MEM / WRITE_MEM */
typedef struct {
    uint64_t target_pid;   /* target process PID (0 = kernel space) */
    uint64_t address;      /* virtual address to read/write          */
    uint32_t size;         /* bytes to transfer (max 4 MB)           */
    uint32_t flags;        /* reserved, set 0                        */
} K0ReadReq;

typedef struct {
    uint64_t target_pid;
    uint64_t address;
    uint32_t size;
    uint32_t flags;
    /* followed immediately by `size` bytes of write data            */
} K0WriteReq;

/* IOCTL_K0_QUERY_REGIONS */
typedef struct {
    uint64_t target_pid;
    uint64_t start_va;     /* scan from this VA (0 = start of space) */
    uint32_t max_regions;  /* how many K0Region entries to return    */
    uint32_t flags;
} K0RegionReq;

typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t protect;      /* PAGE_* constants                       */
    uint32_t state;        /* MEM_COMMIT / MEM_FREE / MEM_RESERVE   */
    uint32_t type;         /* MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE  */
    uint32_t pad;
    char     mapped_file[128]; /* if MEM_IMAGE, module path          */
} K0Region;

/* IOCTL_K0_WATCH_ADD */
#define K0_WATCH_READ       0x01   /* break on read                  */
#define K0_WATCH_WRITE      0x02   /* break on write                 */
#define K0_WATCH_EXEC       0x04   /* break on execute               */

typedef struct {
    uint64_t target_pid;
    uint64_t address;
    uint32_t size;         /* range in bytes (1/2/4/8 for HW BP)    */
    uint32_t access;       /* K0_WATCH_* flags                      */
} K0WatchReq;

typedef struct {
    uint32_t watch_id;     /* opaque ID returned by WATCH_ADD        */
    uint32_t pad;
} K0WatchId;

/* IOCTL_K0_POLL_EVENTS  - ring buffer of change notifications */
#define K0_EVT_MEM_WRITE    0x01   /* watched address was written     */
#define K0_EVT_MEM_READ     0x02   /* watched address was read        */
#define K0_EVT_MEM_EXEC     0x04   /* code executed at watched addr   */
#define K0_EVT_PAGE_CHANGE  0x10   /* arbitrary page content changed  */
#define K0_EVT_ALLOC        0x20   /* new VA region allocated         */
#define K0_EVT_FREE         0x40   /* VA region freed                 */

typedef struct {
    uint64_t timestamp_100ns; /* FILETIME-style 100-ns intervals      */
    uint64_t address;         /* faulting / changed address           */
    uint64_t old_value;       /* up to 8 bytes before                 */
    uint64_t new_value;       /* up to 8 bytes after                  */
    uint32_t pid;
    uint32_t tid;
    uint32_t event_type;      /* K0_EVT_* flags                       */
    uint32_t watch_id;        /* which watchpoint triggered (or 0)    */
    char     context[64];     /* e.g. module name at that address     */
} K0Event;

/* IOCTL_K0_GET_PHYS_ADDR */
typedef struct {
    uint64_t target_pid;
    uint64_t va;
} K0VaToPa;

#pragma pack(pop)

/* -- Max transfer sizes ------------------------------------------- */
#define K0_MAX_READ_BYTES    (4 * 1024 * 1024)   /* 4 MB per IOCTL  */
#define K0_MAX_REGIONS       1024
#define K0_MAX_EVENTS        4096
#define K0_MAX_WATCHPOINTS   4                   /* x86 HW DR0-DR3  */

#endif /* K0PROBE_IFACE_H */
