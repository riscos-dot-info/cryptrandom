#ifndef MACROS_H
#define MACROS_H

#define UNUSED(a) (a=a)

#define system_exit(v) exit(v)
#undef exit
#define exit(v) xsyslogf(SYSLOG_FILE,LOG_ERROR,"Exit called with %d from %s line %d",(v),__FILE__,__LINE__); system_exit(v);

/* #define system_malloc(n) malloc(n)
#undef malloc
#define malloc(n) system_malloc(n)
*/

#define ERROR_OUTOFMEMORY error_outofmemory(__FILE__,__LINE__)

#endif
