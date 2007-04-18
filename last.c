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
 * Copyright (C) 2007 Hanno Hecker
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

/*
 * TODO:
 *  - time changes? i.e. CET -> CEST -> CET
 *  - IPv6 
 */

#define MODULE_NAME "last"
#define LAST_MOD_MAJOR_VERSION 0
#define LAST_MOD_MINOR_VERSION 5
#define MAKING_LAST

#ifdef TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  ifdef HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#if defined(__linux) || defined(__GNU__) 
#  include <utmp.h>
#else
#  include "last_utmp.c"
#endif

#include "src/mod/module.h"
#include "src/users.h"

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

/* show this many lines, can be changed in config file or with -n NUM switch */
static int    last_max_lines    = 20;
static int    last_lines_done   = 0;
static int    last_show_ip      = 0;
static time_t last_until        = 0; /* for -t DATE */

time_t lastdate;    /* Last date we've seen */

/* Double linked list of struct utmp's */
struct utmplist {
  struct utmp ut;
  struct utmplist *next;
  struct utmplist *prev;
};

struct utmplist *utmplist = NULL;

int last_init_wtmp()
{
  FILE *fp;
  if ((fp = fopen(last_wtmp_file, "r")) == NULL) {
    if (errno == ENOENT) {
      /* not existsing -> first load or file removed 
       *  => initialize it with size 0 */
      if ((fp = fopen(last_wtmp_file, "w")) == NULL) {
        putlog(LOG_MISC, "*", 
                "%s.mod: failed to initialize wtmp file `%s': %s'", 
                  MODULE_NAME,
                  last_wtmp_file, 
                  strerror(errno)
              );
        return 0;
      }
    }
    else {
      putlog(LOG_MISC, "*", "%s.mod: failed to initialize wtmp file `%s': %s'", 
                MODULE_NAME,
                last_wtmp_file, 
                strerror(errno)
          );
      return 0; 
    }
  } 
  fclose(fp);
  return 1;
}

static int last_write_wtmp(int idx, int login)
{
  struct utmp entry;

  if (login) 
    entry.ut_type = USER_PROCESS;
  else
    entry.ut_type = DEAD_PROCESS;

  entry.ut_pid  = idx; /* this is unique, so we can use it as PID */
  entry.ut_time = time(NULL);
  /* NICKLEN is usually less than UT_NAMESIZE, but... */
  strncpy(entry.ut_user, dcc[idx].nick, UT_NAMESIZE);
  snprintf(entry.ut_host, UT_HOSTSIZE, "%s", dcc[idx].host);
  snprintf(entry.ut_line, UT_LINESIZE, "idx%d", idx);

  /* FIXME: this is IPv4 ONLY */
  entry.ut_addr = dcc[idx].addr ? dcc[idx].addr : 0; 
  /* FIXME: is this always 4 byte long everywhere? */
  snprintf(entry.ut_id, 4, "%d", idx); 

  if (last_init_wtmp() == 0) 
    return 1;
  updwtmp((const char *)last_wtmp_file, &entry);
  return 0;
}

int last_uread(FILE *fp, struct utmp *u, int *quit)
{
  off_t r;
  if (u == NULL) {
    r = sizeof(struct utmp);
    fseek(fp, -1 * r, SEEK_END);
    return 1;
  }

  r = fread(u, sizeof(struct utmp), 1, fp);
  if (r == 1) {
    if (fseek(fp, -2 * sizeof(struct utmp), SEEK_CUR) < 0) {
      if (quit)
        *quit = 1;
    }
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
  char        *s;
  int         my_mins, my_hours, my_days;
 
  utline[0] = 0;
  strncat(utline, p->ut_line, UT_LINESIZE);

  if (search[0] != 0) {
    if (wild_match(search, p->ut_name) ||
        strcmp(utline, search) == 0 ||
        (strncmp(utline, "idx", 3) == 0 &&
         strcmp(utline + 3, search) == 0) ||
         wild_match(search, p->ut_host)
       ) { /* ok, this is something we have to show */ } 
    else
      return 0;
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
  my_days  = (secs / 86400);
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

  if (last_show_ip) 
    /* FIXME: this is IPv4 ONLY */
    strncpy(domain, iptostr(iptolong(p->ut_addr)), UT_HOSTSIZE);
  else
    strncpy(domain, p->ut_host, UT_HOSTSIZE); 

  snprintf(final, sizeof(final),
              "%-9.9s %-12.12s %-16.16s %-7.7s %-12.12s %s",
              p->ut_name, /* truncated at def NICKLEN of 9 */ 
              utline, 
              logintime, 
              logouttime, 
              length, 
              domain
          );

  /* clean string of unprintable chars */
  for (s = final; *s; s++) {
    if (*s < 32 || (unsigned char)*s > 126)
      *s = '*';
  }
  dprintf(idx, "%s\n", final);

  last_lines_done++;
  if (last_lines_done >= last_max_lines)
    return 1;    

  return 0;
}

int last_read_wtmp(int idx, char *search)
{
  FILE   *fp; /* fh for wtmp file */
  struct stat st;
  time_t last_rec_begin = 0;

  struct utmp ut;        /* Current utmp entry */
  struct utmp oldut;     /* Old utmp entry to check for duplicates */
  struct utmplist *p;    /* Pointer into utmplist */
  struct utmplist *next; /* Pointer into utmplist */

  time_t lastboot = 0;   /* Last boottime */
  time_t lastrch  = 0;   /* Last run level change */
  time_t lastdown = time(NULL);  /* Last downtime */
  int whydown = 0;       /* Why we went down: crash or shutdown */

  int c;         /* Scratch */
  int quit = 0;     /* Flag */
  int down = 0;     /* Down flag */

  last_lines_done = 0;

  if ((fp = fopen(last_wtmp_file, "r")) == NULL) {

    putlog(LOG_MISC, "*", "%s.mod: failed to open wtmp file: %s\n",
                MODULE_NAME, strerror(errno)
           );
    return 0;
  }

  dprintf(idx, 
          "HANDLE    IDX          WHEN                                  HOST\n"
         ); 

  if (last_uread(fp, &ut, NULL) == 1) 
    last_rec_begin = ut.ut_time;
  else {
    fstat(fileno(fp), &st);
    last_rec_begin = st.st_ctime;
    quit = 1;
  }

  /*
   * Go to end of file minus one structure
   * and/or initialize utmp reading code.
   */
  last_uread(fp, NULL, NULL);

  /*
   * Read struct after struct backwards from the file.
   */
  while (!quit) {

    if (last_uread(fp, &ut, &quit) != 1)
      break;

    if (last_until && last_until < ut.ut_time) 
      continue;
        
    if (memcmp(&ut, &oldut, sizeof(struct utmp)) == 0) 
      continue;
    
    memcpy(&oldut, &ut, sizeof(struct utmp));

    lastdate = ut.ut_time;
    if (strncmp(ut.ut_line, "~", 1) == 0) {
      if (strncmp(ut.ut_user, "unload", 6) == 0)
        ut.ut_type = SHUTDOWN_TIME;
      else if (strncmp(ut.ut_user, "modload", 7) == 0)
        ut.ut_type = BOOT_TIME;
    }
        
    switch (ut.ut_type) {
      case SHUTDOWN_TIME:
        if (ut.ut_time)
          lastdown = lastrch = ut.ut_time;
        down = 1;
        break;
      case BOOT_TIME:
        strcpy(ut.ut_line, "system boot");
        quit |= last_display(idx, &ut, lastdown, R_REBOOT, search);
        lastdown = ut.ut_time;
        down = 1;
        break;
      case USER_PROCESS:
        c = 0;
        for (p = utmplist; p; p = next) {
          next = p->next;
          if (strncmp(p->ut.ut_line, ut.ut_line, UT_LINESIZE) == 0) {
            /* show it */
            if (c == 0) {
              quit |= last_display(idx, &ut, p->ut.ut_time, R_NORMAL, search);
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
        if (c == 0) {
          if (lastboot == 0) {
            /* still alive? */
            if (dcc[ut.ut_pid].sock != -1 && 
                strcmp(dcc[ut.ut_pid].nick, ut.ut_name) == 0) 
              c = R_NOW; /* Yes, someone connected on that idx 
                            and nicks are the same */
            else 
              c = R_PHANTOM; /* No */
          }
          else 
            c = whydown;
          
          quit |= last_display(idx, &ut, lastboot, c, search);
        }
        /* no break here! */
      case DEAD_PROCESS:
        if (ut.ut_line[0] == 0)
          break;
        if ((p = nmalloc(sizeof(struct utmplist))) == NULL) {
          putlog(LOG_DEBUG, "*", "%s.mod: out of memory!?", MODULE_NAME);
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
    } /* END switch (ut.ut_type) */

    if (down) {
      if (ut.ut_time) 
        lastboot = ut.ut_time;

      whydown = (ut.ut_type == SHUTDOWN_TIME) ? R_DOWN : R_CRASH;
      for (p = utmplist; p; p = next) {
        next = p->next;
        nfree(p);
      }
      utmplist = NULL;
      down = 0;
    }
  } /* END while (!quit) */

  for (p = utmplist; p; p = next) {
    next = p->next;
    nfree(p);
  }
  utmplist = NULL;
  fclose(fp);
  dprintf(idx, "wtmp file begins %s\n", ctime(&last_rec_begin)); 

  if (last_lines_done > last_max_lines) 
    dprintf(idx, "------ more than %d lines found, truncating -----\n",
                 last_max_lines
           );
  return 0;
}

time_t last_parsetm(char *ts)
{
  struct tm       u = {0}, origu;
  time_t          tm;

  if (sscanf(ts, "%4d%2d%2d%2d%2d%2d", &u.tm_year,
      &u.tm_mon, &u.tm_mday, &u.tm_hour, &u.tm_min,
      &u.tm_sec) != 6)
    return (time_t)-1;

  u.tm_year -= 1900;
  u.tm_mon -= 1;
  u.tm_isdst = -1;

  origu = u;

  if ((tm = mktime(&u)) == (time_t)-1)
    return tm;

  /*
   *      Unfortunately mktime() is much more forgiving than
   *      it should be.  For example, it'll gladly accept
   *      "30" as a valid month number.  This behavior is by
   *      design, but we don't like it, so we want to detect
   *      it and complain.
   */
  if (u.tm_year != origu.tm_year ||
      u.tm_mon != origu.tm_mon ||
      u.tm_mday != origu.tm_mday ||
      u.tm_hour != origu.tm_hour ||
      u.tm_min != origu.tm_min ||
      u.tm_sec != origu.tm_sec)
    return (time_t)-1;

  return tm;
}

static void last_restore_defaults(int max)
{
  last_max_lines = max;
  last_until     = 0; 
  last_show_ip   = 0;
}

static int last_dcc_last(struct userrec *u, int idx, char *par)
{
  char *search;
  char *p, *t, d[15];
  int ret, max, end, m;
  char usage[512] = 
    "last: Usage: last [-n NUM|-NUM] [-i] [-t DATE] [NICK|HOST|IDX]\n"
    "   DATE: YYYYMMDDHHMMSS, missing parts from end will be filled with '0'\n";

  max = last_max_lines;
  end = 0;

  putlog(LOG_CMDS, "*", "#%s# last %s", dcc[idx].nick, par);
  p = newsplit(&par);

  while (p[0] == '-') {
    if (p[1] == 0) {
      last_restore_defaults(max);
      dprintf(idx, usage);
      return 1;
    }

    switch (p[1]) {
      case '-': /* stop option processing if option is '--' */
        end = 1;
        break;

      case 't': /* -t DATE, skip newer than DATE */
        p = newsplit(&par);
        if (p[0] == 0) { 
          last_restore_defaults(max);
          dprintf(idx, usage);
          return 1;
        }

        strncpy(d, p, 14); /* YYYYMMDDHHMMSS */
        /* fill all trailing missing fields with "0" ... */
        m = 0; 
        for (t=p; t[0]; t++) {
          ++m;
        }
        for (; m < 14; m++) {
          switch (m) {
            case 5:
            case 7:        /* 20070000000000 is not a valid date, */
              d[m] = '1';  /* make it 20070101000000 when filling with 0s */
              break;
            default:
              d[m] = '0';
              break;
          }
        }
        d[14] = 0;
        /* ... and parse the given date */
        if ((last_until = last_parsetm(d)) == (time_t)-1) {
          last_restore_defaults(max);
          dprintf(idx, usage);
          return 1;
        }
        break;
        
      case 'i':
        last_show_ip = 1;
        break;

      case 'n': /* -n NUM */
        p = newsplit(&par);
        if (p[0] == 0) {
          last_restore_defaults(max);
          dprintf(idx, usage);
          return 1;
        }
        for (t = p; t[0]; t++) {
          if (!isdigit((unsigned char)t[0])) {
            last_restore_defaults(max);
            dprintf(idx, usage);
            return 1;
          }
        }
        last_max_lines = atoi(p);
        break;

      case '0': /* -NUM */
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        p++;
        for (t = p; t[0]; t++) {
            if (!isdigit((unsigned char)t[0])) {
              last_restore_defaults(max);
              dprintf(idx, usage);
              return 1;
            }
        }
        last_max_lines = atoi(p);
        break;

      default: 
        last_restore_defaults(max);
        dprintf(idx, "last: unknown option '%s'\n", p);
        dprintf(idx, usage);
        return 1;
        break;
    }
    p = newsplit(&par);
    if (end)
      break;
  }

  search = p;
  ret = last_read_wtmp(idx, search);

  last_restore_defaults(max);

  return ret;
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

static tcl_ints last_ints[] = {
  {"last-max-lines",  &last_max_lines},
  {NULL,              NULL}
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
    dprintf(idx, "    Using %d byte%s of memory\n", 
              size, (size != 1) ? "s" : "");
  }
}


static char *last_close()
{
  struct utmp entry;
  entry.ut_type = SHUTDOWN_TIME;
  entry.ut_pid  = 0;
  entry.ut_addr = 0; /* FIXME: this is IPv4 ONLY */
  strcpy(entry.ut_line, "~");
  strcpy(entry.ut_id, "~~");
  entry.ut_time = time(NULL);
  strcpy(entry.ut_user, "unload");
  memset(entry.ut_host,0,UT_HOSTSIZE);
  (void) last_init_wtmp();
  updwtmp((const char *)last_wtmp_file, &entry);

  rem_tcl_strings(last_strings);
  rem_tcl_ints(last_ints);
  rem_builtins(H_dcc, last_dcc);
  rem_builtins(H_chon, last_cmd_chon);
  rem_builtins(H_chof, last_cmd_chof);
  rem_help_reference("last.help");
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
  char modvers[UT_HOSTSIZE+1];
  module_register(MODULE_NAME, last_table, 
                  LAST_MOD_MAJOR_VERSION, LAST_MOD_MINOR_VERSION
                 );
  if (!module_depend(MODULE_NAME, "eggdrop", 106, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.6.0 or later.";
  }
  add_tcl_strings(last_strings);
  add_tcl_ints(last_ints);
  add_builtins(H_dcc,  last_dcc);
  add_builtins(H_chon, last_cmd_chon);
  add_builtins(H_chof, last_cmd_chof);
  add_help_reference("last.help");

  if (last_init_wtmp() == 0)
    return NULL;

  struct utmp entry;
  entry.ut_type = BOOT_TIME;
  entry.ut_pid  = 0;
  entry.ut_addr = 0; /* FIXME: this is IPv4 ONLY */
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

// vim: ts=2 sw=2 expandtab syn=c
