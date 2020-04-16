// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2004 Benjamin Herrenschmidt, IBM Corp.
 *                    <benh@kernel.crashing.org>
 * Copyright (C) 2012 ARM Limited
 * Copyright (C) 2015 Regents of the University of California
 */

#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/binfmts.h>
#include <linux/err.h>
#include <vdso/datapage.h>
#include <asm/timex.h>

extern char vdso_start[], vdso_end[];

static unsigned int vdso_pages;
static unsigned int vdso_data_pages;
static struct page **vdso_pagelist;

/*
 * The vDSO data page.
 */
static union {
	struct vdso_data data;
	u8 page[PAGE_SIZE];
} vdso_data_store __page_aligned_data;
struct vdso_data *vdso_data = &vdso_data_store.data;

static int __init vdso_init(void)
{
	unsigned int i;
	unsigned long *vdso_time_offset;

	if (riscv_time_mmio_pa) {
		vdso_time_offset = (unsigned long *)((unsigned long)vdso_data +
						     PAGE_SIZE -
						     sizeof(unsigned long));
		*vdso_time_offset = (riscv_time_mmio_pa & (PAGE_SIZE - 1));
	}
	vdso_pages = (vdso_end - vdso_start) >> PAGE_SHIFT;
	vdso_data_pages = (riscv_time_mmio_pa) ? 2 : 1;
	vdso_pagelist =
	    kcalloc(vdso_pages + vdso_data_pages, sizeof(struct page *),
		    GFP_KERNEL);
	if (unlikely(vdso_pagelist == NULL)) {
		pr_err("vdso: pagelist allocation failed\n");
		return -ENOMEM;
	}

	for (i = 0; i < vdso_pages; i++) {
		struct page *pg;

		pg = virt_to_page(vdso_start + (i << PAGE_SHIFT));
		vdso_pagelist[i] = pg;
	}
	vdso_pagelist[i] = virt_to_page(vdso_data);
	vdso_pagelist[i + 1] = NULL;

	return 0;
}

arch_initcall(vdso_init);

int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	struct mm_struct *mm = current->mm;
	unsigned long vdso_base, vdso_len;
	struct vm_area_struct *vma;
	int ret;

	vdso_len = (vdso_pages + vdso_data_pages) << PAGE_SHIFT;

	down_write(&mm->mmap_sem);
	vdso_base = get_unmapped_area(NULL, 0, vdso_len, 0, 0);
	if (IS_ERR_VALUE(vdso_base)) {
		ret = vdso_base;
		goto end;
	}

	/*
	 * Put vDSO base into mm struct. We need to do this before calling
	 * install_special_mapping or the perf counter mmap tracking code
	 * will fail to recognise it as a vDSO (since arch_vma_name fails).
	 */
	mm->context.vdso = (void *)vdso_base;

	ret = install_special_mapping(mm, vdso_base, vdso_pages << PAGE_SHIFT,
				      (VM_READ | VM_EXEC | VM_MAYREAD |
				       VM_MAYEXEC), vdso_pagelist);

	if (unlikely(ret)) {
		mm->context.vdso = NULL;
		goto end;
	}

	vdso_base += vdso_pages << PAGE_SHIFT;
	ret = install_special_mapping(mm, vdso_base,
				      vdso_data_pages << PAGE_SHIFT,
				      (VM_READ | VM_MAYREAD),
				      &vdso_pagelist[vdso_pages]);
	if (unlikely(ret)) {
		mm->context.vdso = NULL;
		goto end;
	}

	if (riscv_time_mmio_pa) {
		vma = find_vma(mm, vdso_base + PAGE_SIZE);
		/*Map timer to user space */
		ret = io_remap_pfn_range(vma, vdso_base + PAGE_SIZE,
					 riscv_time_mmio_pa >> PAGE_SHIFT,
					 PAGE_SIZE, vma->vm_page_prot);
		if (ret)
			printk("mtime mapping GG\n");
	}

end:
	up_write(&mm->mmap_sem);
	return ret;
}

const char *arch_vma_name(struct vm_area_struct *vma)
{
	if (vma->vm_mm) {
		if (vma->vm_start == (long)vma->vm_mm->context.vdso)
			return "[vdso]";
		if (vma->vm_start ==
		    ((long)vma->vm_mm->context.vdso + PAGE_SIZE))
			return "[vdso_data]";
	}
	return NULL;
}
