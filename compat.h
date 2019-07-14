/* This code is derived from the Linux Kernel sources intended
 * to maintain compatibility with different Kernel versions.
 * Copyright of original source is of respective Linux Kernel authors.
 * License is GPLv2.
 */

#ifndef COMPAT_NAT_H
#define COMPAT_NAT_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
# define sock_create_kern(f, t, p, s) sock_create_kern(&init_net, f, t, p, s)
#endif

#endif /* COMPAT_NAT_H */

