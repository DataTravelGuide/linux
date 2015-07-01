/*
 *  arch/s390/lib/spinlock.c
 *    Out of line spinlock code.
 *
 *    Copyright (C) IBM Corp. 2004, 2006
 *    Author(s): Martin Schwidefsky (schwidefsky@de.ibm.com)
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <asm/io.h>

int spin_retry = 1000;

/**
 * spin_retry= parameter
 */
static int __init spin_retry_setup(char *str)
{
	spin_retry = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("spin_retry=", spin_retry_setup);

static inline void _raw_yield(void)
{
	if (MACHINE_HAS_DIAG44)
		asm volatile("diag 0,0,0x44");
}

static inline void _raw_yield_cpu(int cpu)
{
	if (MACHINE_HAS_DIAG9C)
		asm volatile("diag %0,0,0x9c"
			     : : "d" (cpu_logical_map(cpu)));
	else
		_raw_yield();
}

void _raw_spin_lock_wait(raw_spinlock_t *lp)
{
	int count = spin_retry;
	unsigned int cpu = SPINLOCK_LOCKVAL;
	unsigned int owner;

	while (1) {
		owner = lp->lock;
		if (!owner || smp_vcpu_scheduled(~owner)) {
			for (count = spin_retry; count > 0; count--) {
				if (__raw_spin_is_locked(lp))
					continue;
				if (_raw_compare_and_swap(&lp->lock, 0, cpu))
					return;
			}
			if (!MACHINE_IS_VM)
				continue;
		}
		owner = lp->lock;
		if (owner)
			_raw_yield_cpu(~owner);
		if (_raw_compare_and_swap(&lp->lock, 0, cpu))
			return;
	}
}
EXPORT_SYMBOL(_raw_spin_lock_wait);

void _raw_spin_lock_wait_flags(raw_spinlock_t *lp, unsigned long flags)
{
	int count = spin_retry;
	unsigned int cpu = SPINLOCK_LOCKVAL;
	unsigned int owner;

	local_irq_restore(flags);
	while (1) {
		owner = lp->lock;
		if (!owner || smp_vcpu_scheduled(~owner)) {
			for (count = spin_retry; count > 0; count--) {
				if (__raw_spin_is_locked(lp))
					continue;
				local_irq_disable();
				if (_raw_compare_and_swap(&lp->lock, 0, cpu))
					return;
				local_irq_restore(flags);
			}
			if (!MACHINE_IS_VM)
				continue;
		}
		owner = lp->lock;
		if (owner)
			_raw_yield_cpu(~owner);
		local_irq_disable();
		if (_raw_compare_and_swap(&lp->lock, 0, cpu))
			return;
		local_irq_restore(flags);
	}
}
EXPORT_SYMBOL(_raw_spin_lock_wait_flags);

void _raw_spin_relax(raw_spinlock_t *lp)
{
	unsigned int cpu = lp->lock;
	if (cpu != 0) {
		if (MACHINE_IS_VM || MACHINE_IS_KVM ||
		    !smp_vcpu_scheduled(~cpu))
			_raw_yield_cpu(~cpu);
	}
}
EXPORT_SYMBOL(_raw_spin_relax);

int _raw_spin_trylock_retry(raw_spinlock_t *lp)
{
	int count;

	for (count = spin_retry; count > 0; count--)
		if (__raw_spin_trylock_once(lp))
			return 1;
	return 0;
}
EXPORT_SYMBOL(_raw_spin_trylock_retry);

void _raw_read_lock_wait(raw_rwlock_t *rw)
{
	unsigned int old;
	int count = spin_retry;

	while (1) {
		if (count-- <= 0) {
			_raw_yield();
			count = spin_retry;
		}
		old = ACCESS_ONCE(rw->lock);
		if ((int) old < 0)
			continue;
		if (_raw_compare_and_swap(&rw->lock, old, old + 1))
			return;
	}
}
EXPORT_SYMBOL(_raw_read_lock_wait);

void _raw_read_lock_wait_flags(raw_rwlock_t *rw, unsigned long flags)
{
	unsigned int old;
	int count = spin_retry;

	local_irq_restore(flags);
	while (1) {
		if (count-- <= 0) {
			_raw_yield();
			count = spin_retry;
		}
		old = ACCESS_ONCE(rw->lock);
		if ((int) old < 0)
			continue;
		local_irq_disable();
		if (_raw_compare_and_swap(&rw->lock, old, old + 1))
			return;
		local_irq_restore(flags);
	}
}
EXPORT_SYMBOL(_raw_read_lock_wait_flags);

int _raw_read_trylock_retry(raw_rwlock_t *rw)
{
	unsigned int old;
	int count = spin_retry;

	while (count-- > 0) {
		old = ACCESS_ONCE(rw->lock);
		if ((int) old < 0)
			continue;
		if (_raw_compare_and_swap(&rw->lock, old, old + 1))
			return 1;
	}
	return 0;
}
EXPORT_SYMBOL(_raw_read_trylock_retry);

void _raw_write_lock_wait(raw_rwlock_t *rw)
{
	unsigned int old;
	int count = spin_retry;

	while (1) {
		if (count-- <= 0) {
			_raw_yield();
			count = spin_retry;
		}
		old = ACCESS_ONCE(rw->lock);
		if (old)
			continue;
		if (_raw_compare_and_swap(&rw->lock, 0, 0x80000000))
			return;
	}
}
EXPORT_SYMBOL(_raw_write_lock_wait);

void _raw_write_lock_wait_flags(raw_rwlock_t *rw, unsigned long flags)
{
	unsigned int old;
	int count = spin_retry;

	local_irq_restore(flags);
	while (1) {
		if (count-- <= 0) {
			_raw_yield();
			count = spin_retry;
		}
		old = ACCESS_ONCE(rw->lock);
		if (old)
			continue;
		local_irq_disable();
		if (_raw_compare_and_swap(&rw->lock, 0, 0x80000000))
			return;
		local_irq_restore(flags);
	}
}
EXPORT_SYMBOL(_raw_write_lock_wait_flags);

int _raw_write_trylock_retry(raw_rwlock_t *rw)
{
	unsigned int old;
	int count = spin_retry;

	while (count-- > 0) {
		old = ACCESS_ONCE(rw->lock);
		if (old)
			continue;
		if (_raw_compare_and_swap(&rw->lock, 0, 0x80000000))
			return 1;
	}
	return 0;
}
EXPORT_SYMBOL(_raw_write_trylock_retry);
