#ifndef _LINUX_KHUGEPAGED_H
#define _LINUX_KHUGEPAGED_H

#include <linux/sched.h> /* MMF_VM_HUGEPAGE */

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
extern int __khugepaged_enter(struct mm_struct *mm);
extern void __khugepaged_exit(struct mm_struct *mm);

static inline int khugepaged_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	if (test_bit(MMF_VM_HUGEPAGE, &oldmm->flags))
		return __khugepaged_enter(mm);
	return 0;
}

static inline void khugepaged_exit(struct mm_struct *mm)
{
	if (test_bit(MMF_VM_HUGEPAGE, &mm->flags))
		__khugepaged_exit(mm);
}
#else /* CONFIG_TRANSPARENT_HUGEPAGE */
static inline int khugepaged_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	return 0;
}
static inline void khugepaged_exit(struct mm_struct *mm)
{
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#endif /* _LINUX_KHUGEPAGED_H */
