.PATH:  ${SRCTOP}/sys/dev/iwx

KMOD    = if_iwx
SRCS    = if_iwx.c device_if.h bus_if.h pci_if.h opt_iwx.h opt_wlan.h

CFLAGS	+= -Wno-error=missing-prototypes -Wno-error=unused-but-set-variable
CFLAGS	+= -I${SRCTOP}/sys/dev/iwx/openbsd_network/compat/
CFLAGS	+= -I${SRCTOP}/sys/dev/iwx/openbsd_wlan/compat/
CFLAGS	+= -I${SRCTOP}/sys/dev/iwx/openbsd_wlan/

.include <bsd.kmod.mk>
