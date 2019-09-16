#include <linux/ptrace.h>
#include <linux/kdebug.h>
#include <linux/bug.h>
#include <linux/kgdb.h>
#include <linux/irqflags.h>
#include <asm/cacheflush.h>
#include <asm/string.h>

enum {
	NOT_KGDB_BREAK = 0,
	KGDB_SW_BREAK,
	KGDB_COMPILED_BREAK,
};
/*TODO: currently, only gpr is filled. The required system register does not be included because I do not which system register required by gdb, and I also do not know the sequence number of these system registers in gdb*/
struct dbg_reg_def_t dbg_reg_def[DBG_MAX_REG_NUM] = {
	{"zero", GDB_SIZEOF_REG, -1},
	{"ra", GDB_SIZEOF_REG, offsetof(struct pt_regs, ra)},
	{"sp", GDB_SIZEOF_REG, offsetof(struct pt_regs, sp)},
	{"gp", GDB_SIZEOF_REG, offsetof(struct pt_regs, gp)},
	{"tp", GDB_SIZEOF_REG, offsetof(struct pt_regs, tp)},
	{"t0", GDB_SIZEOF_REG, offsetof(struct pt_regs, t0)},
	{"t1", GDB_SIZEOF_REG, offsetof(struct pt_regs, t1)},
	{"t2", GDB_SIZEOF_REG, offsetof(struct pt_regs, t2)},
	{"s0", GDB_SIZEOF_REG, offsetof(struct pt_regs, s0)},
	{"s1", GDB_SIZEOF_REG, offsetof(struct pt_regs, a1)},
	{"a0", GDB_SIZEOF_REG, offsetof(struct pt_regs, a0)},
	{"a1", GDB_SIZEOF_REG, offsetof(struct pt_regs, a1)},
	{"a2", GDB_SIZEOF_REG, offsetof(struct pt_regs, a2)},
	{"a3", GDB_SIZEOF_REG, offsetof(struct pt_regs, a3)},
	{"a4", GDB_SIZEOF_REG, offsetof(struct pt_regs, a4)},
	{"a5", GDB_SIZEOF_REG, offsetof(struct pt_regs, a5)},
	{"a6", GDB_SIZEOF_REG, offsetof(struct pt_regs, a6)},
	{"a7", GDB_SIZEOF_REG, offsetof(struct pt_regs, a7)},
	{"s2", GDB_SIZEOF_REG, offsetof(struct pt_regs, s2)},
	{"s3", GDB_SIZEOF_REG, offsetof(struct pt_regs, s3)},
	{"s4", GDB_SIZEOF_REG, offsetof(struct pt_regs, s4)},
	{"s5", GDB_SIZEOF_REG, offsetof(struct pt_regs, s5)},
	{"s6", GDB_SIZEOF_REG, offsetof(struct pt_regs, s6)},
	{"s7", GDB_SIZEOF_REG, offsetof(struct pt_regs, s7)},
	{"s8", GDB_SIZEOF_REG, offsetof(struct pt_regs, s8)},
	{"s9", GDB_SIZEOF_REG, offsetof(struct pt_regs, s9)},
	{"s10", GDB_SIZEOF_REG, offsetof(struct pt_regs, s10)},
	{"s11", GDB_SIZEOF_REG, offsetof(struct pt_regs, s11)},
	{"t3", GDB_SIZEOF_REG, offsetof(struct pt_regs, t3)},
	{"t4", GDB_SIZEOF_REG, offsetof(struct pt_regs, t4)},
	{"t5", GDB_SIZEOF_REG, offsetof(struct pt_regs, t5)},
	{"t6", GDB_SIZEOF_REG, offsetof(struct pt_regs, t6)},
	{"pc", GDB_SIZEOF_REG, offsetof(struct pt_regs, sepc)},
};
char *dbg_get_reg(int regno, void *mem, struct pt_regs *regs)
{
	if (regno >= DBG_MAX_REG_NUM || regno < 0)
		return NULL;

	if (dbg_reg_def[regno].offset != -1)
		memcpy(mem, (void *)regs + dbg_reg_def[regno].offset,
		       dbg_reg_def[regno].size);
	else
		memset(mem, 0, dbg_reg_def[regno].size);
	return dbg_reg_def[regno].name;
}

int dbg_set_reg(int regno, void *mem, struct pt_regs *regs)
{
	if (regno >= DBG_MAX_REG_NUM || regno < 0)
		return -EINVAL;

	if (dbg_reg_def[regno].offset != -1)
		memcpy((void *)regs + dbg_reg_def[regno].offset, mem,
		       dbg_reg_def[regno].size);
	return 0;
}

void
sleeping_thread_to_gdb_regs(unsigned long *gdb_regs, struct task_struct *task)
{
	/* Initialize to zero */
	memset((char *)gdb_regs, 0, NUMREGBYTES);

	gdb_regs[1] = task->thread.ra;
	gdb_regs[2] = task->thread.sp;
	gdb_regs[8] = task->thread.s[0];
	gdb_regs[9] = task->thread.s[1];
	gdb_regs[18] = task->thread.s[2];
	gdb_regs[19] = task->thread.s[3];
	gdb_regs[20] = task->thread.s[4];
	gdb_regs[21] = task->thread.s[5];
	gdb_regs[22] = task->thread.s[6];
	gdb_regs[23] = task->thread.s[7];
	gdb_regs[24] = task->thread.s[8];
	gdb_regs[25] = task->thread.s[10];
	gdb_regs[26] = task->thread.s[11];
}

void kgdb_arch_set_pc(struct pt_regs *regs, unsigned long pc)
{
	regs->sepc = pc;
}

/*
 * Handle the 'c' command
 */
int kgdb_arch_handle_exception(int vector, int signo, int err_code,
			       char *remcom_in_buffer, char *remcom_out_buffer,
			       struct pt_regs *regs)
{
	char *ptr;
	unsigned long address;

	switch (remcom_in_buffer[0]) {
	case 'c':
		/* handle the optional parameter */
		ptr = &remcom_in_buffer[1];
		if (kgdb_hex2long(&ptr, &address)) {
			regs->sepc = address;
		}
		return 0;
	}

	return -1;
}

void arch_kgdb_breakpoint(void)
{
	asm(".global kgdb_compiled_break\n"
	    ".option norvc\n"
	    "kgdb_compiled_break:" "ebreak\n" ".option rvc\n");
}

extern int kgdb_ishitbreak(unsigned long addr);
int kgdb_riscv_kgdbbreak(unsigned long addr)
{
	if (atomic_read(&kgdb_setting_breakpoint))
		if (addr == (unsigned long)kgdb_compiled_break)
			return KGDB_COMPILED_BREAK;

	return kgdb_ishitbreak(addr);
}

static int kgdb_riscv_notify(struct notifier_block *self, unsigned long cmd,
			     void *ptr)
{
	struct die_args *args = (struct die_args *)ptr;
	struct pt_regs *regs = args->regs;
	unsigned long flags;
	int type;

	if (user_mode(regs))
		return NOTIFY_DONE;

	type = kgdb_riscv_kgdbbreak(regs->sepc);
	if (type == NOT_KGDB_BREAK && cmd == DIE_TRAP)
		return NOTIFY_DONE;

	local_irq_save(flags);
	if (kgdb_handle_exception(1, args->signr, cmd, regs)) {
		return NOTIFY_DONE;
	}

	if (type == KGDB_COMPILED_BREAK)
		regs->sepc += 4;

	local_irq_restore(flags);
	flush_icache_all();

	return NOTIFY_STOP;
}

static struct notifier_block kgdb_notifier = {
	.notifier_call = kgdb_riscv_notify,
};

int kgdb_arch_init(void)
{
	register_die_notifier(&kgdb_notifier);

	return 0;
}

void kgdb_arch_exit(void)
{
	unregister_die_notifier(&kgdb_notifier);
}

/*
 * Global data
 */
const struct kgdb_arch arch_kgdb_ops = {
	.gdb_bpt_instr = {0x73, 0x00, 0x10, 0x00},	/* ebreak */
};
