#ifndef __ASM_KGDB_H_
#define __ASM_KGDB_H_

#ifdef __KERNEL__

#define GDB_SIZEOF_REG sizeof(unsigned long)

/* TODO Currently, only gp register is counted */
/*      It needs to find the MAX num which gdb can support */
#define DBG_MAX_REG_NUM (33)
#define NUMREGBYTES (DBG_MAX_REG_NUM * GDB_SIZEOF_REG)
#define CACHE_FLUSH_IS_SAFE     1
#define BUFMAX                  2048
#define BREAK_INSTR_SIZE	4

#define CACHE_FLUSH_IS_SAFE 1

extern void arch_kgdb_breakpoint(void);
extern void kgdb_compiled_break(void);

#endif
#endif
