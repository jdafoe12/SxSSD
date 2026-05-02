#ifndef __FEMU_MEM_BACKEND
#define __FEMU_MEM_BACKEND

#include <stdint.h>

/* DRAM backend SSD address space */
typedef struct SsdDramBackend {
    void    *backend_memory;
    int64_t size; /* in bytes */
    int     femu_mode;
} SsdDramBackend;

int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes);
void free_dram_backend(SsdDramBackend *);

int backend_rw(SsdDramBackend *, QEMUSGList *, uint64_t *, uint64_t, bool,
               uint64_t, uint64_t);

/* Copy len bytes from qsg at byte offset start_off into buf. Does not destroy qsg. */
int backend_sglist_read(QEMUSGList *qsg, uint8_t *buf, uint64_t len, uint64_t start_off);

#endif
