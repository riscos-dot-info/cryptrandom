#include <stdio.h>
#include "kernel.h"

#include "def.h"
#include "macros.h"
#include "vartypes.h"
#include "sysstruc.h"

OSERROR error_nullptr = {0x815111, "Null pointer supplied"};

static OSERROR err;

OSERROR *error_outofmemory(char *file,int line)
{
  err.errnum=0x815110;
  sprintf(err.errmess,"Out of memory, %s line %d",file,line);

  return &err;
}
