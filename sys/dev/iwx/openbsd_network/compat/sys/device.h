/*
 * Copyright 2022, Haiku, Inc. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef _OBSD_COMPAT_SYS_DEVICE_H_
#define _OBSD_COMPAT_SYS_DEVICE_H_


#include <sys/firmware.h>


static inline int
loadfirmware(const char *name, u_char **bufp, size_t *buflen)
{
	const struct firmware* fw = firmware_get(name);
	if (fw == NULL)
		return -1;

	*bufp = __DECONST(u_char *, fw->data);
	*buflen = fw->datasize;

	// Caller takes ownership of data.
	//fw->data = NULL;
	firmware_put(fw, 0);
	return 0;
}


#endif	/* _OBSD_COMPAT_SYS_DEVICE_H_ */
