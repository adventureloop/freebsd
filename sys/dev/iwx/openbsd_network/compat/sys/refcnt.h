/*
 * Copyright 2022, Haiku, Inc. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef _OBSD_COMPAT_SYS_REFCNT_H_
#define _OBSD_COMPAT_SYS_REFCNT_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <machine/atomic.h>

#define int32 		int
#define atomic_set	atomic_set_32
#define atomic_add	atomic_add_32

struct refcnt {
	int32	r_refs;
};


#define REFCNT_INITIALIZER()		{ .r_refs = 1 }


static void
refcnt_init(struct refcnt* r)
{
	atomic_set_32(&r->r_refs, 1);
}

static void
refcnt_take(struct refcnt* r)
{
	atomic_add_32(&r->r_refs, 1);
}

static int
refcnt_rele(struct refcnt* r)
{
	atomic_add(&r->r_refs, -1);
	KASSERT(r->r_refs >= 0, "OpenBSD iwx");
	if (r->r_refs == 0)
		return 1;
	return 0;
}

static void
refcnt_rele_wake(struct refcnt* r)
{
	if (refcnt_rele(r))
		wakeup_one(r);
}

static void
refcnt_finalize(struct refcnt* r, const char* wmesg)
{
	refcnt_rele(r);
	while (r->r_refs > 0)
		tsleep(r, PWAIT, wmesg, 0);
}


#endif	/* _OBSD_COMPAT_SYS_REFCNT_H_ */
