/*
 * Copyright 2022, Haiku, Inc. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef _OBSD_COMPAT_SYS_RWLOCK_H_
#define _OBSD_COMPAT_SYS_RWLOCK_H_

#include <sys/mutex.h>
#include <sys/lock.h>
#include <sys/rwlock.h>

#if 0
struct rwlock_openbsd {
	struct rw_lock lock;
};
#define rwlock rwlock_openbsd
#else
//struct rwlock;
#endif

#if 0
static inline void
rw_init_flags(struct rwlock* rwl, const char* name, int flags)
{
	rw_lock_init(&rwl->lock, name);
}
#define rw_init(rwl, name)	rw_init_flags(rwl, name, 0)
#endif

#define RW_WRITE		0x0001UL
#define RW_READ			0x0002UL
#define RW_OPMASK		0x0007UL

#define RW_INTR			0x0010UL

static int
rw_enter(struct rwlock* rwl, int flags)
{
	const int op = (flags & RW_OPMASK);
	const int giant = mtx_owned(&Giant);
	if (giant)
		mtx_unlock(&Giant);

	if (op == RW_WRITE)
		rw_wlock(rwl);
	else if (op == RW_READ)
		rw_rlock(rwl);
	else
		panic("bad rw op");

	if (giant)
		mtx_lock(&Giant);
	return (0);
}

static inline int
rw_enter_write(struct rwlock* rwl)
{
	return rw_enter(rwl, RW_WRITE);
}

static inline void
rw_exit(struct rwlock* rwl)
{
	rw_wunlock(rwl);
}

#define KDEBUG 0
static inline void
rw_assert_wrlock(struct rwlock* rwl)
{
#if KDEBUG
	if (rwl->lock.holder != find_thread(NULL))
		panic("rw_assert_wrlock failed!");
#endif
}


#endif	/* _OBSD_COMPAT_SYS_RWLOCK_H_ */
