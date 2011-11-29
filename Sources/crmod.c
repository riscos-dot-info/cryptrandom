#include "kernel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oslib/os.h"

#include "vartypes.h"
#include "macros.h"
#include "def.h"
#include "moddef.h"

#include "sysstruc.h"
#include "syslogif.h"
#include "event.h"
#include "noise.h"
#include "randputty.h"
#include "error.h"
#include "sha.h"
#include "version.h"

static void *module_globalPrivateWord=NULL;

OSERROR *module_swi(int swiNumber, _kernel_swi_regs *r, void *privateWord)
{
  OSERROR *result=NULL;
  UNUSED(privateWord);
  UNUSED(swiNumber);
  UNUSED(r);
  xsyslog_irq_mode(TRUE);

  switch(swiNumber)
  {
    case CryptRandom_Byte:
      _kernel_irqs_off();
      r->r[0]=random_byte();
      _kernel_irqs_on();
      break;
    case CryptRandom_AddNoise:
      if (r->r[0]!=NULL)
      {
        _kernel_irqs_off();
        random_add_noise((void *) r->r[0],r->r[1]);
        _kernel_irqs_on();
      }
      else
        result=&error_nullptr;
      break;
    case CryptRandom_Stir:
      _kernel_irqs_off();
      random_stir();
      _kernel_irqs_on();
      break;
    case CryptRandom_Block:
      _kernel_irqs_off();
      random_block((void *) r->r[0],r->r[1]);
      _kernel_irqs_on();
    case CryptRandom_Word:
      _kernel_irqs_off();
      r->r[0]=random_word();
      _kernel_irqs_on();
      break;
    default:
      break;
  }

  xsyslog_irq_mode(FALSE);
  return result;
}

OSERROR *module_cmd(char *argString, int argc, int commandNumber, void *privateWord)
{
  UNUSED(privateWord);
  UNUSED(argString);
  UNUSED(argc);
  UNUSED(commandNumber);
  xsyslog_irq_mode(TRUE);

  version_printlicence();

  xsyslog_irq_mode(FALSE);
  return 0;
}

void module_service(int serviceNumber, _kernel_swi_regs *r, void *privateWord)
{
  UNUSED(serviceNumber);
  UNUSED(r);
  UNUSED(privateWord);

  /* Only interested in Service_ShutDown */

  xsyslog_irq_mode(TRUE);
  noise_save_seed();

  xsyslog_irq_mode(FALSE);
}

void module_finalise(void)
{
  xsyslog_irq_mode(TRUE);

  xsyslog_irq_logf(SYSLOG_FILE,LOG_INIT,"Killing CryptRandom...\n");
  event_finalise(module_globalPrivateWord);

  noise_save_seed();
  xsyslog_irq_mode(FALSE);
}

OSERROR *module_initialise(char *commandTail, int poduleBase, void *privateWord)
{
  OSERROR *result;

  UNUSED(commandTail);
  UNUSED(poduleBase);
  UNUSED(privateWord);
  xsyslog_irq_mode(TRUE);

  module_globalPrivateWord=privateWord;

  xsyslog_irq_logf(SYSLOG_FILE,LOG_INIT,"Starting CryptRandom...\n");

  random_init();

  result=event_initialise(module_globalPrivateWord);

  if (result)
  {
    xsyslog_irq_logf(SYSLOG_FILE,LOG_ERROR,"Error in event_initialise: %x, %d, %s\n",result,result->errnum,result->errmess);
    xsyslog_irq_mode(FALSE);
    exit(1);
  }

  /* if everything here went OK, we can attach the normal finalisation
   * code - don't do this before here, as we might try to finalise
   * something that hasn't been initialised
   */
  atexit(module_finalise);
  xsyslog_irq_mode(FALSE);

  return 0;
}


