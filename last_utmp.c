/*
 * most of this is glibc 2.3.1 - modified ...
 *
 *
 * $Revision$
 * $Id$
 */

#include <sys/types.h>
#include <unistd.h>
#include <sys/file.h>
#include <stdio.h>

#define UT_UNKNOWN            0
#define RUN_LVL               1
#define BOOT_TIME             2
#define NEW_TIME              3
#define OLD_TIME              4
#define INIT_PROCESS          5
#define LOGIN_PROCESS         6
#define USER_PROCESS          7
#define DEAD_PROCESS          8
#define ACCOUNTING            9

#define UT_LINESIZE           12
#define UT_NAMESIZE           32
#define UT_HOSTSIZE           256

struct exit_status {
    short int e_termination;    /* process termination status */
    short int e_exit;           /* process exit status */
};


struct utmp {
    short ut_type;              /* type of login */
    pid_t ut_pid;               /* pid of login process */
    char ut_line[UT_LINESIZE];  /* device name of tty - "/dev/" */
    char ut_id[4];              /* init id or abbrev. ttyname */
    char ut_user[UT_NAMESIZE];  /* user name */
    char ut_host[UT_HOSTSIZE];  /* hostname for remote login */
    struct exit_status ut_exit; /* The exit status of a process
                                   marked as DEAD_PROCESS. */
    long ut_session;            /* session ID, used for windowing*/
    struct timeval ut_tv;       /* time entry was made.  */
    int32_t ut_addr_v6[4];      /* IP address of remote host.  */
    char __unused[20];          /* Reserved for future use.  */
};

/* Backwards compatibility hacks.  */
#define ut_name ut_user
#ifndef _NO_UT_TIME
#define ut_time ut_tv.tv_sec
#endif
#define ut_xtime ut_tv.tv_sec
#define ut_addr ut_addr_v6[0]

void updwtmp(const char *wtmp_file, const struct utmp *ut)
{
    int fd;
    int i;
    off_t offset;
    int locked = 0;

    fd = open(wtmp_file, O_WRONLY);
    if (fd < 0)
        return;

    for (i = 0; i <= 3; i++) {
        if (flock(fd, LOCK_EX|LOCK_NB) == 0) {
            locked = 1;
            break;
        }
        usleep(250); 
    }
    if (!locked) {
        close(fd);
        return;    
    }

    offset = lseek(fd, 0, SEEK_END);
    if (offset % sizeof(struct utmp) != 0) {
        offset -= offset % sizeof(struct utmp);
        ftruncate(fd, offset);
        if (lseek(fd, 0, SEEK_END) < 0)
            goto unlock_return;
    }

    if (write(fd, ut, sizeof(struct utmp)) != sizeof(struct utmp)) 
        ftruncate(fd, offset);

    fsync(fd);
  unlock_return:
    flock(fd, LOCK_UN);
    close(fd);
    return;
}
