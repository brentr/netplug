/*
 * if_info.c - track network interface information
 *
 * Copyright 2003 PathScale, Inc.
 * Copyright 2003, 2004, 2005 Bryan O'Sullivan
 * Copyright 2003 Jeremy Fitzhardinge
 *  Heavily Revised:  1/9/24 brent@mbari.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.  You are
 * forbidden from redistributing or modifying it under the terms of
 * any other license, including other versions of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <time.h>
#include <wait.h>
#include <net/if.h>

#include "netplug.h"

#define INFOHASHSZ      16      /* must be a power of 2 */
static struct if_info *if_info[INFOHASHSZ];

static const char *
statename(enum ifstate s)
{
    switch(s) {
#define S(x)    case ST_##x: return #x
        S(UNKNOWN);
        S(INACTIVE);
        S(ACTIVE);
#undef S
    default: return "???";
    }
}

static const char *
flags_str(char *buf, unsigned int fl)
{
    static struct flag {
        const char *name;
        unsigned int flag;
    } flags[] = {
#define  F(x)   { #x, IFF_##x }
        F(UP),
        F(BROADCAST),
        F(DEBUG),
        F(LOOPBACK),
        F(POINTOPOINT),
        F(NOTRAILERS),
        F(RUNNING),
        F(NOARP),
        F(PROMISC),
        F(ALLMULTI),
        F(MASTER),
        F(SLAVE),
        F(MULTICAST),
#undef F
    };
    char *cp = buf;

    *cp = '\0';

    for(int i = 0; i < sizeof(flags)/sizeof(*flags); i++) {
        if (fl & flags[i].flag) {
            fl &= ~flags[i].flag;
            cp += sprintf(cp, "%s,", flags[i].name);
        }
    }

    if (fl != 0)
        cp += sprintf(cp, "%x,", fl);

    if (cp != buf)
        cp[-1] = '\0';

    return buf;
}

void
for_each_iface(int (*func)(struct if_info *))
{
    for(int i = 0; i < INFOHASHSZ; i++) {
        for(struct if_info *info = if_info[i]; info != NULL; info = info->next) {
            if ((*func)(info))
                return;
        }
    }
}

#define ifReady(flags) ((flags) & IFF_RUNNING)

/* Reevaluate the state machine based on the current state and flag settings */
void
ifsm_flagpoll(struct if_info *info)
{
    enum ifstate state = info->state;

    switch(state) {
      case ST_UNKNOWN:
        info->state = ifReady(info->flags) ? ST_ACTIVE : ST_INACTIVE;
        return;

      case ST_INACTIVE:
        if (ifReady(info->flags) && info->worker == -1) {
          info->worker = run_netplug_bg(info->name, "in");
          info->state = ST_ACTIVE;
        }
        break;

      case ST_ACTIVE:
        if (!ifReady(info->flags)) {
          if (info->worker == -1)
              kill_script(info->worker);  //"in" script will not succeed
          info->worker = run_netplug_bg(info->name, "out");
          info->state = ST_INACTIVE;
        }
        break;
    }

    if (info->state != state)
        do_log(LOG_DEBUG, "%s became %s", info->name, statename(info->state));
}

/* if_info state transitions caused by interface flag changes */
void
ifsm_flagchange(struct if_info *info, unsigned int newflags)
{
    if (ifReady(info->flags ^ newflags)) {
      char buf1[512], buf2[512];
      do_log(LOG_INFO, "%s: state %s flags 0x%08x %s -> 0x%08x %s", info->name,
             statename(info->state),
             info->flags, flags_str(buf1, info->flags),
             newflags, flags_str(buf2, newflags));

      info->flags = newflags;
      ifsm_flagpoll(info);
    }
}

/* handle a script termination and update the state accordingly */
void ifsm_scriptdone(pid_t pid, int exitstatus)
{
    struct if_info *info;
    assert(WIFEXITED(exitstatus) || WIFSIGNALED(exitstatus));

    int find_pid(struct if_info *i) {
        if (i->worker == pid) {
            info = i;
            return 1;
        }
        return 0;
    }

    info = NULL;
    for_each_iface(find_pid);

    if (info == NULL) {
        do_log(LOG_WARNING, "Unexpected child pid %d exited with status %d",
               pid, WEXITSTATUS(exitstatus));
        return;
    }
    do_log(LOG_INFO, "%s: state %s pid %d exited with status %d",
           info->name, statename(info->state), pid, WEXITSTATUS(exitstatus));

    info->worker = -1;
    ifsm_flagpoll(info);
}

void
parse_rtattrs(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(tb) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta,len);
    }
    if (len) {
        do_log(LOG_ERR, "Badness! Deficit %d, rta_len=%d", len, rta->rta_len);
        abort();
    }
}

int if_info_save_interface(struct nlmsghdr *hdr, void *arg)
{
    struct rtattr *attrs[IFLA_MAX + 1];
    struct ifinfomsg *info = NLMSG_DATA(hdr);

    parse_rtattrs(attrs, IFLA_MAX, IFLA_RTA(info), IFLA_PAYLOAD(hdr));

    return if_info_update_interface(hdr, attrs) ? 0 : -1;
}


struct if_info *
if_info_get_interface(struct nlmsghdr *hdr, struct rtattr *attrs[])
{
    if (hdr->nlmsg_type != RTM_NEWLINK && hdr->nlmsg_type != RTM_DELLINK) {
        return NULL;
    }

    struct ifinfomsg *info = NLMSG_DATA(hdr);

    if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(info))) {
        return NULL;
    }

    if (attrs[IFLA_IFNAME] == NULL) {
        return NULL;
    }

    int x = info->ifi_index & (INFOHASHSZ-1);
    struct if_info *i, **ip;

    for (ip = &if_info[x]; (i = *ip) != NULL; ip = &i->next) {
        if (i->index == info->ifi_index) {
            break;
        }
    }

    if (i == NULL) {  //add new interface
        i = xmalloc(sizeof(*i));
        i->next = *ip;
        i->index = info->ifi_index;
        *ip = i;

        /* initialize state machine fields */
        i->state = initialIfState;
        i->worker = -1;
    }else
      if (hdr->nlmsg_type == RTM_DELLINK) {  //remove deleted interface
        *ip = i->next;
        free(i);
        return NULL;
    }
    return i;
}


struct if_info *
if_info_update_interface(struct nlmsghdr *hdr, struct rtattr *attrs[])
{
    struct ifinfomsg *info = NLMSG_DATA(hdr);
    struct if_info *i;

    if ((i = if_info_get_interface(hdr, attrs)) == NULL) {
        return NULL;
    }

    i->type = info->ifi_type;
    i->flags = info->ifi_flags;

    if (attrs[IFLA_ADDRESS]) {
        int alen;
        i->addr_len = alen = RTA_PAYLOAD(attrs[IFLA_ADDRESS]);
        if (alen > sizeof(i->addr))
            alen = sizeof(i->addr);
        memcpy(i->addr, RTA_DATA(attrs[IFLA_ADDRESS]), alen);
    } else {
        i->addr_len = 0;
        memset(i->addr, 0, sizeof(i->addr));
    }

    strcpy(i->name, RTA_DATA(attrs[IFLA_IFNAME]));

    return i;
}
