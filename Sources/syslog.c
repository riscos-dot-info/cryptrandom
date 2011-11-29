#include <stdio.h>
#include <stdarg.h>
#include "kernel.h"
#include "oslib/syslog.h"

#include "def.h"
#include "macros.h"
#include "vartypes.h"
#include "sysstruc.h"
#include "syslogif.h"

/* Module safe versions of syslogf and xsyslogf - Doggysoft versions
 * didn't handle multiple instantiation
 */

static char buffer[SYSLOG_BUFFER];

_kernel_oserror *xsyslog_irq_logf(const char *logname, int priority,
                                 const char *format, ...)
{
  va_list ap;
  register int r;
  _kernel_oserror *result;

  xsyslog_irq_mode(TRUE);
  va_start (ap, format);
  r = vsprintf (buffer, format, ap);
  va_end (ap);

  result=xsyslog_log_message(logname,buffer,priority);
  xsyslog_irq_mode(FALSE);

  return result;
}


void syslog_irq_logf(const char *logname, int priority,
                                 const char *format, ...)
{
  va_list ap;
  register int r;

  syslog_irq_mode(TRUE);
  va_start (ap, format);
  r = vsprintf (buffer, format, ap);
  va_end (ap);

  syslog_log_message(logname,buffer,priority);
  syslog_irq_mode(FALSE);

}

_kernel_oserror *xsyslog_logf(const char *logname, int priority,
                                 const char *format, ...)
{
  va_list ap;
  register int r;
  _kernel_oserror *result;

  va_start (ap, format);
  r = vsprintf (buffer, format, ap);
  va_end (ap);

  result=xsyslog_log_message(logname,buffer,priority);

  return result;
}


void syslog_logf(const char *logname, int priority,
                                 const char *format, ...)
{
  va_list ap;
  register int r;

  va_start (ap, format);
  r = vsprintf (buffer, format, ap);
  va_end (ap);

  syslog_log_message(logname,buffer,priority);
}

OSERROR *xsyslog_irq_report(OSERROR *err,char *file,int line)
{
  if (err)
    xsyslog_irq_logf(SYSLOG_FILE,LOG_ERROR, "Error: %s line %d error %d: %s\n",file,line,err->errnum,err->errmess);
  return err;
}
