#include "kernel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vartypes.h"
#include "macros.h"
#include "def.h"
#include "moddef.h"

#include "sysstruc.h"
#include "sha.h"
#include "version.h"

static void *module_globalPrivateWord=NULL;


OSERROR *module_cmd(char *argString, int argc, int commandNumber, void *privateWord)
{
  UNUSED(privateWord);
  UNUSED(argString);
  UNUSED(argc);
  UNUSED(commandNumber);

  version_printlicence();

  return 0;
}


OSERROR *module_swi(int swiNumber, _kernel_swi_regs *r, void *privateWord)
{
  OSERROR *result=NULL;
  UNUSED(privateWord);
  UNUSED(swiNumber);
  UNUSED(r);

  switch(swiNumber)
  {
    case SHA1_Digest:
      result = sha_digest(r->r[0], (void *) r->r[1], r->r[2], (int *) r->r[3]);
      break;
  }

  return result;
}
