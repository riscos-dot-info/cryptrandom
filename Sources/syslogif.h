/* Called syslogif.h to prevent clashes with NetLib/BSD syslog.h */

#ifndef SYSLOGIF_H
#define SYSLOGIF_H

#include "syslogDS.h"

#define syslog_irq_logmessage          syslog_logmessage
#define syslog_irq_logunstamped        syslog_logunstamped
#define syslog_irq_logdata             syslog_logdata
#define syslog_irq_logformatted        syslog_logformatted
#define syslog_irq_irqmode             syslog_irqmode
#define syslog_irq_getloglevel         syslog_getloglevel
#define syslog_irq_indent              syslog_indent
#define syslog_irq_unindent            syslog_unindent
#define syslog_irq_noindent            syslog_noindent
#define syslog_irq_readerrormessage    syslog_readerrormessage

#define xsyslog_irq_logmessage          xsyslog_logmessage
#define xsyslog_irq_logunstamped        xsyslog_logunstamped
#define xsyslog_irq_logdata             xsyslog_logdata
#define xsyslog_irq_logformatted        xsyslog_logformatted
#define xsyslog_irq_irqmode             xsyslog_irqmode
#define xsyslog_irq_getloglevel         xsyslog_getloglevel
#define xsyslog_irq_indent              xsyslog_indent
#define xsyslog_irq_unindent            xsyslog_unindent
#define xsyslog_irq_noindent            xsyslog_noindent
#define xsyslog_irq_readerrormessage    xsyslog_readerrormessage

#define syslogf syslog_logf
#define xsyslogf xsyslog_logf

typedef int syslog_SessionHandle;

#define SYSLOG_FILE "CryptRand"
#define SYSLOG_BUFFER 4096

#define SYSLOG_ENTRY(proc) xsyslog_irq_logf(SYSLOG_FILE, LOG_DEBUG_TRACE, "entering %s\n",proc)

#define SYSLOG_EXIT(proc) xsyslog_irq_logf(SYSLOG_FILE, LOG_DEBUG_TRACE, "exiting %s\n",proc)

#define REPORT(err) xsyslog_irq_report(err,__FILE__,__LINE__)
#define DEBUG(level,msg) xsyslog_logmessage(SYSLOG_FILE,level,msg)

extern void dprintf(const char *format,...);

extern _kernel_oserror *xsyslog_irq_logf(const char *logname, int priority,
                                 const char *format, ...);
extern void syslog_irq_logf(const char *logname, int priority,
                                 const char *format, ...);
extern _kernel_oserror *xsyslog_logf(const char *logname, int priority,
                                 const char *format, ...);
extern void syslog_logf(const char *logname, int priority,
                                 const char *format, ...);
extern OSERROR *xsyslog_irq_report(OSERROR *err,char *file,int line);


#endif

