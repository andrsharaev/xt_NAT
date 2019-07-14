KVER   ?= $(shell uname -r)
KDIR   ?= /lib/modules/$(KVER)/build/
DEPMOD  = /sbin/depmod -a
CC     ?= gcc
obj-m   = xt_NAT.o
CFLAGS_xt_NAT.o := -DDEBUG

all: xt_NAT.ko libxt_NAT.so

xt_NAT.ko: xt_NAT.c
	make -C $(KDIR) M=$(CURDIR) modules CONFIG_DEBUG_INFO=y
	-sync

%_sh.o: libxt_NAT.c
	gcc -O2 -Wall -Wunused -fPIC -o $@ -c $<

%.so: %_sh.o
	gcc -shared -o $@ $<

sparse: clean | xt_NAT.c xt_NAT.h
	make -C $(KDIR) M=$(CURDIR) modules C=1

cppcheck:
	cppcheck -I $(KDIR)/include --enable=all --inconclusive xt_NAT.c
	cppcheck libxt_NAT.c

coverity:
	coverity-submit -v

clean:
	make -C $(KDIR) M=$(CURDIR) clean
	-rm -f *.so *_sh.o *.o modules.order

install: | minstall linstall

minstall: | xt_NAT.ko
	make -C $(KDIR) M=$(CURDIR) modules_install INSTALL_MOD_PATH=$(DESTDIR)

linstall: libxt_NAT.so
	install -D $< $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/$<

uninstall:
	-rm -f $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/libxt_NAT.so
	-rm -f $(KDIR)/extra/xt_NAT.ko

load: all
	-sync
	-modprobe x_tables
	-mkdir -p /lib64/modules/`uname -r`/kernel/net/ipv4/
	-cp xt_NAT.ko /lib64/modules/`uname -r`/kernel/net/ipv4/
	-depmod `uname -r`
	-modprobe xt_NAT
	-iptables-restore < iptables.rules
	-conntrack -F
unload:
	-/etc/init.d/iptables restart
	-rmmod xt_NAT.ko
del:
	-sync
reload: unload clean load

.PHONY: all minstall linstall install uninstall clean cppcheck
