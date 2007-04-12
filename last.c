/*
 * last.c -- part of last.mod
 *    last(1) style wtmp records for eggdrop partyline logins
 *
 *    by Hanno Hecker <vetinari@ankh-morp.org>
 *
 * parts of this mod were taken from sysvinit 2.86
 *   (last.c: Version: @(#)last  2.85  30-Jul-2004  miquels@cistron.nl)
 *
 * $Revision$
 * $Id$
 *
 */
/*
 * Copyright (C) 2007 Hano Hecker
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define MODULE_NAME "last"
#define LAST_MOD_MAJOR_VERSION 0
#define LAST_MOD_MINOR_VERSION 1
#define MAKING_LAST

#include "src/mod/module.h"
#include "src/users.h"

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utmp.h>
#include <stdlib.h>

#ifndef SHUTDOWN_TIME
#  define SHUTDOWN_TIME 254
#endif

/* Types of listing */
#define R_CRASH     1 /* No logout record, system boot in between */
#define R_DOWN      2 /* System brought down in decent way */
#define R_NORMAL    3 /* Normal */
#define R_NOW       4 /* Still logged in */
#define R_REBOOT    5 /* Reboot record. */
#define R_PHANTOM   6 /* No logout record but session is stale. */
#define R_TIMECHANGE    7 /* NEW_TIME or OLD_TIME */

static Function *global = NULL;

/* file where all logins are saved */
static char last_wtmp_file[121] = "Eggdrop.last";

static int last_max_lines       = 20;
static int last_recs_done       = 0;
time_t lastdate;    /* Last date we've seen */
/* Double linked list of struct utmp's */
struct utmplist {
  struct utmp ut;
  struct utmplist *next;
  struct utmplist *prev;
};
struct utmplist *utmplist = NULL;

static int last_write_wtmp(int idx, int login)
{
    struct utmp entry;
    char temp[512];

    entry.ut_pid  = idx;
    entry.ut_addr = dcc[idx].addr;
    entry.ut_pid  = idx;
    entry.ut_time = time(NULL);
    strcpy(entry.ut_user, dcc[idx].nick);

    sprintf(temp, "%s", 
                dcc[idx].addr ?  iptostr(htonl(dcc[idx].addr)) : dcc[idx].host
           );
    strcpy(entry.ut_host, temp);

    sprintf(temp, "%d", idx);
    strcpy(entry.ut_id,   temp);
    sprintf(temp, "idx%d", idx);
    // memset(&entry.ut_line, 0, UT_LINESIZE);
    strcpy(entry.ut_line, temp);

    if (login) 
        entry.ut_type = USER_PROCESS;
    else
        entry.ut_type = DEAD_PROCESS;

    updwtmp((const char *)last_wtmp_file, &entry);
    return 0;
}

int last_uread(FILE *fp, struct utmp *u, int *quit)
{
    off_t r;
    if (u == NULL) 
    {
        r = sizeof(struct utmp);
        fseek(fp, -1 * r, SEEK_END);
        return 1;
    }

    r = fread(u, sizeof(struct utmp), 1, fp);
    if (r == 1)
    {
        if (fseeko(fp, -2 * sizeof(struct utmp), SEEK_CUR) < 0)
            if (quit)
                *quit = 1;
        if (ftell(fp) == 0 && quit)
            *quit = 1;
    }
    return r;
}

int last_display(int idx, struct utmp *p, time_t t, int what, char *search)
{
    time_t      secs, tmp;
    char        logintime[32];
    char        logouttime[32];
    char        length[32];
    char        final[128];
    char        utline[UT_LINESIZE+1];
    char        domain[256];
    char        *s, *walk;
    int         my_mins, my_hours, my_days;
    int         r, len;
 
    utline[0] = 0;
    strncat(utline, p->ut_line, UT_LINESIZE);

    if (search[0] != 0) {
        for (walk = search; walk[0] != 0; walk++) {
            if (strncasecmp(p->ut_name, walk, UT_NAMESIZE) == 0 ||
                strcmp(utline, walk) == 0 ||
                (strncmp(utline, "idx", 3) == 0 &&
                 strcmp(utline + 3, walk) == 0) ||
                 strncmp(p->ut_host, walk, UT_HOSTSIZE) == 0
               ) break;
        }
        if (walk[0] == 0) return 0;
    }
    /*
     *  Calculate times
     */
    tmp = (time_t)p->ut_time;
    strcpy(logintime, ctime(&tmp));
    logintime[16] = 0;
    sprintf(logouttime, "- %s", ctime(&t) + 11);
    logouttime[7] = 0;
    secs = t - p->ut_time;
    my_mins  = (secs / 60) % 60;
    my_hours = (secs / 3600) % 24;
    my_days  = (secs / 86400) % 86400;
    if (my_days)
        sprintf(length, "(%d+%02d:%02d)", my_days, my_hours, my_mins);
    else
        sprintf(length, " (%02d:%02d)", my_hours, my_mins);

    switch (what) {
        case R_CRASH:
            sprintf(logouttime, "- crash");
            break;
        case R_DOWN:
            sprintf(logouttime, "- down ");
            break;
        case R_NOW:
            length[0] = 0;
            sprintf(logouttime, "  still");
            sprintf(length, "logged in");
            break;
        case R_PHANTOM:
            length[0] = 0;
            sprintf(logouttime, "   gone");
            sprintf(length, "- no logout");
            break;
        case R_REBOOT:
            logouttime[0] = 0;      /* Print machine uptime */
            break;
        case R_TIMECHANGE:
            logouttime[0] = 0;
            length[0] = 0;
            break;
        case R_NORMAL:
            break;
    }
    
    strncpy(domain, p->ut_host, UT_HOSTSIZE); 
    snprintf(final, sizeof(final),
                "%-9.9s %-12.12s %-16.16s %-7.7s %-12.12s %s",
                p->ut_name, utline, 
                logintime, logouttime, length, domain
            );
    for (s = final; *s; s++) 
    {
        if (*s < 32 || (unsigned char)*s > 126)
            *s = '*';
    }
    dprintf(idx, "%s\n", final);

    last_recs_done++;
    if (last_recs_done >= last_max_lines)
        return 1;    

    return 0;
}

int last_read_wtmp(int idx, char *search)
{
    FILE   *fp; /* fh for wtmp file */
    struct stat st;
    time_t    last_rec_begin = 0;

    struct utmp ut;   /* Current utmp entry */
    struct utmp oldut;    /* Old utmp entry to check for duplicates */
    struct utmplist *p;   /* Pointer into utmplist */
    struct utmplist *next;/* Pointer into utmplist */

    time_t lastboot = 0; // time(NULL);  /* Last boottime */
    time_t lastrch  = 0;   /* Last run level change */
    time_t lastdown = time(NULL);  /* Last downtime */
    int whydown = 0;  /* Why we went down: crash or shutdown */

    int c, x;     /* Scratch */
    int quit = 0;     /* Flag */
    int down = 0;     /* Down flag */

    time_t until = 0; /* at what time to stop parsing the file */

    last_recs_done = 0;
    if ((fp = fopen(last_wtmp_file, "r")) == NULL) 
    {
        dprintf(idx, "%s.mod: failed to open wtmp file: %s\n", 
                    MODULE_NAME, strerror(errno)
              );
        return 0;
    }

    if (last_uread(fp, &ut, NULL) == 1) 
        last_rec_begin = ut.ut_time;
    else 
    {
        fstat(fileno(fp), &st);
        last_rec_begin = st.st_ctime;
        quit      = 1;
    }

    /*
     * Go to end of file minus one structure
     * and/or initialize utmp reading code.
     */
    last_uread(fp, NULL, NULL);

    /*
     * Read struct after struct backwards from the file.
     */
    while (!quit) 
    {
        if (last_uread(fp, &ut, &quit) != 1)
            break;

        if (until && until < ut.ut_time) 
            continue;
        
        if (memcmp(&ut, &oldut, sizeof(struct utmp)) == 0) 
            continue;
        memcpy(&oldut, &ut, sizeof(struct utmp));

        lastdate = ut.ut_time;
        if (strncmp(ut.ut_line, "~", 1) == 0)
        {
            if (strncmp(ut.ut_user, "unload", 6) == 0)
                ut.ut_type = SHUTDOWN_TIME;
            else if (strncmp(ut.ut_user, "modload", 7) == 0)
                ut.ut_type = BOOT_TIME;
        }
        
        switch (ut.ut_type) 
        {
            case SHUTDOWN_TIME:
                lastdown = lastrch = ut.ut_time;
                down = 1;
                break;
            case BOOT_TIME:
                strcpy(ut.ut_line, "system boot");
                quit = last_display(idx, &ut, lastdown, R_REBOOT, search);
                down = 1;
                break;
            case USER_PROCESS:
                c = 0;
                for (p = utmplist; p; p = next) 
                {
                    next = p->next;
                    if (strncmp(p->ut.ut_line, ut.ut_line, UT_LINESIZE) == 0) 
                    {
                        /* show it */
                        if (c == 0) 
                        {
                            quit = last_display(idx, &ut, p->ut.ut_time, R_NORMAL, search);
                            c = 1;
                        }
                        if (p->next) 
                            p->next->prev = p->prev;
                        if (p->prev)
                            p->prev->next = p->next;
                        else
                            utmplist = p->next;
                        nfree(p);
                    }
                }
                /* not found? -> crashed, down, still logged in or
                 * logout missing:
                 */
                if (c == 0)
                {
                    if (lastboot == 0)
                    {
                        c = R_NOW;
                        /* still alive? */
                        if (dcc[ut.ut_pid].sock == -1)
                            c = R_PHANTOM;

                    }
                    else 
                        c = whydown;
                    quit = last_display(idx, &ut, lastboot, c, search);
                }
                /* no break here! */
            case DEAD_PROCESS:
                if (ut.ut_line[0] == 0)
                    break;
                if ((p = nmalloc(sizeof(struct utmplist))) == NULL) 
                {
                    putlog(LOG_DEBUG, "*", "%s.mod: out of memory!?", 
                                      MODULE_NAME
                          );
                    quit = 1;
                    return 1;
                }
                memcpy(&p->ut, &ut, sizeof(struct utmp));
                p->next  = utmplist;
                p->prev  = NULL;
                if (utmplist) 
                    utmplist->prev = p;
                utmplist = p;
                break;
        }
        if (down == 1) 
        {
            lastboot = ut.ut_time;
            whydown = (ut.ut_type == SHUTDOWN_TIME) ? R_DOWN : R_CRASH;
            for (p = utmplist; p; p = next) 
            {
                next = p->next;
                nfree(p);
            }
            utmplist = NULL;
            down = 0;
        }
    }
    for (p = utmplist; p; p = next) {
        next = p->next;
        nfree(p);
    }
    utmplist = NULL;
    fclose(fp);
    dprintf(idx, "wtmp file begins %s\n", ctime(&last_rec_begin)); 

    if (last_recs_done >= last_max_lines) 
        dprintf(idx, "------ more than %d lines found, truncating -----\n",
                    last_max_lines
               );
    return 0;
}

static int last_dcc_last(struct userrec *u, int idx, char *par)
{
    char *search;
    putlog(LOG_CMDS, "*", "#%s# last %s", dcc[idx].nick, par);
    dprintf(idx, "HANDLE    IDX          WHEN                                  HOST\n"); 
    search = newsplit(&par);
    return last_read_wtmp(idx, search);
}

static int last_chon(char *handle, int idx) 
{
    (void) last_write_wtmp(idx, 1);
    return 0;
}

static int last_chof(char *handle, int idx) 
{
    (void) last_write_wtmp(idx, 0);
    return 0;
}

static cmd_t last_dcc[] = {
    {"last", "",   last_dcc_last, NULL},
    {NULL,   NULL, NULL,     NULL}
};
static cmd_t last_cmd_chon[] = {
    {"*",    "", last_chon, "last:chon"},
    {NULL,   NULL, NULL,     NULL}
};
static cmd_t last_cmd_chof[] = {
    {"*",    "", last_chof, "last:chof"},
    {NULL,   NULL, NULL,     NULL}
};
static tcl_strings last_strings[] = {
    {"last-wtmp-file",   last_wtmp_file,      120, STR_PROTECT},
    {NULL,          NULL,           0,             0}
};

static int last_expmem()
{
    return 0;
}

/* Report on current seen info for .modulestat. */
static void last_report(int idx, int details)
{
    if (details) {
        int size = last_expmem();

        dprintf(idx, "    Using %d byte%s of memory\n", size,
            (size != 1) ? "s" : "");
    }
}


static char *last_close()
{
    struct utmp entry;
    entry.ut_type = SHUTDOWN_TIME;
    entry.ut_pid  = 0;
    strcpy(entry.ut_line, "~");
    strcpy(entry.ut_id, "~~");
    entry.ut_time = 0;
    strcpy(entry.ut_user, "unload");
    memset(entry.ut_host,0,UT_HOSTSIZE);
    entry.ut_addr=0;
    updwtmp((const char *)last_wtmp_file, &entry);

    p_tcl_bind_list H_temp;
    rem_builtins(H_dcc, last_dcc);
    rem_builtins(H_chon, last_cmd_chon);
    rem_builtins(H_chof, last_cmd_chof);
    // rem_help_reference("last.help");
    module_undepend(MODULE_NAME);
    return NULL;
}

EXPORT_SCOPE char *last_start();

static Function last_table[] = {
    (Function) last_start,
    (Function) last_close,
    (Function) last_expmem,
    (Function) last_report,
};

char *last_start(Function *egg_func_table)
{
    global = egg_func_table;
    FILE *fp;
    char modvers[UT_HOSTSIZE+1];
    if ((fp = fopen(last_wtmp_file, "r")) == NULL && errno == ENOENT) 
    {
        if ((fp = fopen(last_wtmp_file, "w")) == NULL)
        {
            putlog(LOG_MISC, "*", 
                "%s.mod: failed to initialize wtmp file `%s': %s'", 
                MODULE_NAME,
                last_wtmp_file, 
                strerror(errno)
            );
            return NULL;
        }
    } 
    fclose(fp);

    module_register(MODULE_NAME, last_table, 
                    LAST_MOD_MAJOR_VERSION, 
                    LAST_MOD_MINOR_VERSION
                   );
    if (!module_depend(MODULE_NAME, "eggdrop", 106, 0)) {
        module_undepend(MODULE_NAME);
        return "This module requires Eggdrop 1.6.0 or later.";
    }
    add_tcl_strings(last_strings);
    add_builtins(H_dcc,  last_dcc);
    add_builtins(H_chon, last_cmd_chon);
    add_builtins(H_chof, last_cmd_chof);

    // add_help_reference("last.help");
    struct utmp entry;
    entry.ut_type = BOOT_TIME;
    entry.ut_pid  = 0;
    entry.ut_addr = 0;
    entry.ut_time = time(NULL);
    strcpy(entry.ut_line,  "~");
    strcpy(entry.ut_id,    "~~");
    strcpy(entry.ut_user,  "modload");
    snprintf(modvers, UT_HOSTSIZE, "%s.mod %d.%d", 
                                    MODULE_NAME, 
                                    LAST_MOD_MAJOR_VERSION, 
                                    LAST_MOD_MINOR_VERSION
            );
    strncpy(entry.ut_host, modvers, UT_HOSTSIZE);
    updwtmp((const char *)last_wtmp_file, &entry);
    return NULL;
}


// vim: ts=4 sw=4 expandtab syn=c
