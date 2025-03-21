/*
 * main.c - daemon startup and link monitoring
 *
 * Copyright 2003 PathScale, Inc.
 * Copyright 2003, 2004, 2005 Bryan O'Sullivan
 * Copyright 2003 Jeremy Fitzhardinge
 *  Simplified/debugged:  1/9/24 brent@mbari.org
 *    Removed concept of "probing" interfaces so downed interfaces stay down!
 *    Reduced number of internal interface states from 11 to 3!!
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

#define _GNU_SOURCE
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <assert.h>
#include <wait.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

#include "netplug.h"

enum ifstate initialIfState = ST_UNKNOWN;

int use_syslog;
static char *pid_file;

static int
handle_interface(struct nlmsghdr *hdr, void *arg)
{
    if (hdr->nlmsg_type != RTM_NEWLINK && hdr->nlmsg_type != RTM_DELLINK) {
        return 0;
    }

    struct ifinfomsg *info = NLMSG_DATA(hdr);
    int len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*info));

    if (info->ifi_flags & IFF_LOOPBACK) {
        return 0;
    }

    if (len < 0) {
        do_log(LOG_ERR, "Malformed netlink packet length");
        return -1;
    }

    struct rtattr *attrs[IFLA_MAX + 1];

    parse_rtattrs(attrs, IFLA_MAX, IFLA_RTA(info), len);

    if (attrs[IFLA_IFNAME] == NULL) {
        do_log(LOG_ERR, "No interface name");
        return -1;
    }

    char *name = RTA_DATA(attrs[IFLA_IFNAME]);

    if (!if_match(name)) {
        do_log(LOG_INFO, "%s: ignoring event", name);
        return 0;
    }

    struct if_info *i = if_info_get_interface(hdr, attrs);

    if (i == NULL)
        return 0;

    ifsm_flagchange(i, info->ifi_flags);

    if_info_update_interface(hdr, attrs);

    return 0;
}


static void
usage(char *progname, int exitcode)
{
    fprintf(stderr, "Usage: %s [-DFud] [-c config-file] "
        "[-s script-file] [-i interface] [-p pid-file]\n"
        "Revised: 3/18/25 brent@mbari.org\n", progname);

    fprintf(stderr,
    "\t-u UP interfaces initially if they have carrier\n"
    "\t-d DOWN interfaces initially if they have no carrier\n"
    "\t-D\t\t"
            "print extra debugging messages\n"
    "\t-F\t\t"
            "run in foreground (don't become a daemon)\n"
    "\t-c config_file\t"
            "read interface patterns from this config file\n"
    "\t-i interface\t"
            "only handle interfaces matching this pattern\n"
    "\t-p pid_file\t"
            "write daemon process ID to pid_file\n");

    exit(exitcode);
}


static void
write_pid(void)
{
    FILE *fp;

    if ((fp = fopen(pid_file, "w")) == NULL) {
        do_log(LOG_ERR, "%s: %m", pid_file);
        return;
    }

    fprintf(fp, "%d\n", getpid());
    fclose(fp);
}

static void
tidy_pid(void)
{
    if (pid_file) {
        unlink(pid_file);
        pid_file = NULL;
    }
}

static void
exit_handler(int sig)
{
    tidy_pid();
    do_log(sig==SIGTERM ? LOG_INFO:LOG_ERR, "caught signal %d - exiting", sig);
    exit(1);
}

struct child_exit
{
    pid_t       pid;
    int         status;
};

static int child_handler_pipe[2];

static void
child_handler(int sig, siginfo_t *info, void *v)
{
    struct child_exit ce;
    int ret;

    assert(sig == SIGCHLD);

    ce.pid = info->si_pid;
    ret = waitpid(info->si_pid, &ce.status, 0);
    if (ret == info->si_pid) {
        ssize_t s = write(child_handler_pipe[1], &ce, sizeof(ce));

	  if (s == -1) {
	      do_log(LOG_ERR, "can't write into pipe");
	      exit(1);
	  }
    }
}

int debug = 0;

int
main(int argc, char *argv[])
{
    int foreground = 0;
    int cfg_read = 0;
    int c;

    while ((c = getopt(argc, argv, "udDFPc:s:hi:p:")) != EOF) {
        switch (c) {
        case 'D':
            debug = 1;
            break;
        case 'F':
            foreground = 1;
            break;
        case 'c':
            read_config(optarg);
            cfg_read = 1;
            break;
        case 's':
            script_file = optarg;
            break;
        case 'h':
            fprintf(stderr, "netplugd version %s\n", NP_VERSION);
            usage(argv[0], 0);
            break;
        case 'i':
            if (save_pattern(optarg) == -1) {
                fprintf(stderr, "Bad pattern for '-i %s'\n", optarg);
                exit(1);
            }
            break;
        case 'u':
            initialIfState = ST_INACTIVE;
            break;
        case 'd':
            initialIfState = ST_ACTIVE;
            break;
        case 'p':
            pid_file = optarg;
            break;
        case '?':
            usage(argv[0], 1);
        }
    }

    if (!cfg_read) {
        read_config(NP_ETC_DIR "/netplugd.conf");
    }

    if (getuid() != 0) {
        do_log(LOG_WARNING, "This daemon will not work properly unless "
               "run by root");
    }

    struct sigaction act = {
        .sa_handler = exit_handler,
        .sa_flags = SA_ONESHOT | SA_NOMASK,
    };

    if (sigaction(SIGHUP, &act, NULL) == -1) {
        do_log(LOG_ERR, "can't catch hangup signal: %m");
        exit(1);
    }

    if (sigaction(SIGINT, &act, NULL) == -1) {
        do_log(LOG_ERR, "can't catch interrupt signal: %m");
        exit(1);
    }

    if (sigaction(SIGTERM, &act, NULL) == -1) {
        do_log(LOG_ERR, "can't catch termination signal: %m");
        exit(1);
    }

    if (!foreground) {
        use_syslog = 1;
        openlog("netplugd", LOG_PID, LOG_DAEMON);
    }

    if (pipe(child_handler_pipe) == -1) {
        do_log(LOG_ERR, "can't create pipe: %m");
        exit(1);
    }

    close_on_exec(child_handler_pipe[0]);
    close_on_exec(child_handler_pipe[1]);

    if (fcntl(child_handler_pipe[0], F_SETFL, O_NONBLOCK) == -1) {
        do_log(LOG_ERR, "can't set pipe non-blocking: %m");
        exit(1);
    }

    struct sigaction sa;
    sa.sa_sigaction = child_handler;
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
    sigfillset(&sa.sa_mask);

    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        do_log(LOG_ERR, "can't set SIGCHLD handler: %m");
        exit(1);
    }

    int fd = netlink_open();

    netlink_request_dump(fd);
    netlink_receive_dump(fd, if_info_save_interface, NULL);

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        do_log(LOG_ERR, "can't set socket non-blocking: %m");
        exit(1);
    }

    if (!foreground) {
	if (daemon(0, 0) == -1) {
	    do_log(LOG_ERR, "daemon: %m");
	    exit(1);
	}

        if (pid_file) {
            atexit(tidy_pid);
            write_pid();
        }
    }

    struct pollfd fds[] = {
        { fd, POLLIN, 0 },
        { child_handler_pipe[0], POLLIN, 0 },
    };

    {
        /* Run over each of the interfaces we know and care about, and
           make sure the state machine has done the appropriate thing
           for their current state. */
        int poll_flags(struct if_info *i) {
            if (if_match(i->name))
                ifsm_flagpoll(i);
            return 0;
        }
        for_each_iface(poll_flags);
    }

    for(;;) {
        int ret;

        /* Make sure we don't miss anything interesting */
        ret = poll(fds, sizeof(fds)/sizeof(fds[0]), -1);

        if (ret == -1) {
            if (errno == EINTR)
                continue;
            do_log(LOG_ERR, "poll failed: %m");
            exit(1);
        }
        if (ret == 0) {         /* XXX??? */
            sleep(1);           /* don't spin */
            continue;
        }

        if (fds[0].revents & POLLIN) {
            /* interface flag state change */
            if (netlink_listen(fd, handle_interface, NULL) == 0)
                break;          /* done */
        }

        if (fds[1].revents & POLLIN) {
            /* netplug script finished */
            int ret;
            struct child_exit ce;

            do {
                ret = read(child_handler_pipe[0], &ce, sizeof(ce));

                assert(ret == 0 || ret == -1 || ret == sizeof(ce));

                if (ret == sizeof(ce))
                    ifsm_scriptdone(ce.pid, ce.status);
                else if (ret == -1 && errno != EAGAIN) {
                    do_log(LOG_ERR, "pipe read failed: %m");
                    exit(1);
                }
            } while(ret == sizeof(ce));
        }
    }

    return 0;
}


/*
 * Local variables:
 * c-file-style: "stroustrup"
 * End:
 */
