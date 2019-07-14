#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include "xt_NAT.h"

enum {
    F_SNAT  = 1 << 0,
    F_DNAT  = 1 << 1,
};

static const struct option nat_tg_opts[] = {
    {.name = "snat", .has_arg = false, .val = 's'},
    {.name = "dnat", .has_arg = false, .val = 'd'},
    {NULL},
};

static void nat_tg_help(void)
{
    printf(
        "NAT target options:\n"
        "  --snat    Create NAT translation from Inside to Outside\n"
        "  --dnat    Allow NAT for revert traffic from Outside to Inside\n");
}

static int nat_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
    struct xt_nat_tginfo *info = (void *)(*target)->data;

    switch (c) {
    case 's':
        info->variant = XTNAT_SNAT;
        *flags |= F_SNAT;
        return true;
    case 'd':
        info->variant = XTNAT_DNAT;
        *flags |= F_DNAT;
        return true;
    }
    return false;
}

static void nat_tg_check(unsigned int flags)
{
    if (flags == (F_SNAT | F_DNAT))
        xtables_error(PARAMETER_PROBLEM,
                      "NAT: only one action can be used at a time");
}

static void nat_tg_save(const void *ip,
                        const struct xt_entry_target *target)
{
    const struct xt_nat_tginfo *info = (const void *)target->data;

    switch (info->variant) {
    case XTNAT_SNAT:
        printf(" --snat ");
        break;
    case XTNAT_DNAT:
        printf(" --dnat ");
        break;
    }
}

static void nat_tg_print(const void *ip,
                         const struct xt_entry_target *target, int numeric)
{
    printf(" -j NAT");
    nat_tg_save(ip, target);
}

static struct xtables_target nat_tg_reg = {
    .version       = XTABLES_VERSION,
    .name          = "NAT",
    .family        = NFPROTO_IPV4,
    .size          = XT_ALIGN(sizeof(struct xt_nat_tginfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_nat_tginfo)),
    .help          = nat_tg_help,
    .parse         = nat_tg_parse,
    .final_check   = nat_tg_check,
    .print         = nat_tg_print,
    .save          = nat_tg_save,
    .extra_opts    = nat_tg_opts,
};

static __attribute__((constructor)) void nat_tg_ldr(void)
{
    xtables_register_target(&nat_tg_reg);
}

