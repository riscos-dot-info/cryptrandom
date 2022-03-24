#include "kernel.h"
#include "oslib/os.h"
#include "oslib/osbyte.h"
#include "oslib/syslog.h"

#include "def.h"
#include "vartypes.h"
#include "macros.h"
#include "sysstruc.h"

#include "noise.h"
#include "putty.h"
#include "syslogif.h"

extern int event_eventv_entry(_kernel_swi_regs *r, void *pw);
/*extern int event_mousev_entry(_kernel_swi_regs *r, void *pw);
extern int event_callback_entry(_kernel_swi_regs *r, void *pw);*/

int event_eventv_handler(_kernel_swi_regs *r, void *pw)
{
  uint32 buffer[1];

  if (r->r[0]!=Event_KeyTransition)
    return 1; /* asap */

  xsyslog_irq_mode(TRUE);

  /*buffer[0]=r->r[1]; - key up/down is usually a set sequence - not random */
  buffer[0]=r->r[2];

  xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_VERYLOW,"noise %d\n",buffer[0]);
  noise_get_ultralight(random_add_noise,buffer,sizeof(buffer));

  xsyslog_irq_mode(FALSE);
  return 1;
}

#if 0
static int mouseX=0,mouseY=0,button=0,buttonTime=0;

int event_mousev_handler(_kernel_swi_regs *r, void *pw)
{
  xsyslog_irqmode(TRUE);

  if (mouseX==r->r[0])
    if (mouseY==r->r[1])
      if (button==r->r[2])
        if (buttonTime==r->r[3])
        {
          xsyslog_irq_mode(FALSE);
          return 1;
        }

  mouseX=r->r[0];
  mouseY=r->r[1];
  button=r->r[2];
  buttonTime=r->r[3];

  /* slight hack here - lose a STM/LDM by adding directly from
   * _kernel_swi_regs struct - 16 is 4 regs * 4 bytes
   */
  noise_get_ultralight(random_add_noise,&(r->r[0]),16);
  xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_VERYLOW,"noise %d,%d,%d,%d\n",r->r[0],r->r[1],r->r[2],r->r[3]);
  xsyslog_irq_mode(FALSE);

  return 1;
}

int event_callback_handler(_kernel_swi_regs *r, void *pw)
{
  return 1;
}
#endif

OSERROR *event_initialise(void *privateWord)
{
  OSERROR *result=0;

  result=(OSERROR *) xos_claim(EventV,(void *) event_eventv_entry,privateWord);
  xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_VERYLOW,"event_initialise: claim eventv result=%p\n",result);

  if (!result)
  {
    result=(OSERROR *) xosbyte(osbyte_ENABLE_EVENT,Event_KeyTransition,0);
    xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_VERYLOW,"event_initialise: enable event result=%p\n",result);

    if (result)
      return result;
  }
  else
    return result;

  /* MouseV generates too many adjacent events - just read pos in EventV instead */
/*  result=(OSERROR *) xos_claim(MouseV,(void *) event_mousev_entry,privateWord);
  xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_VERYLOW,"event_initialise: claim mousev result=\n",result);*/

  return result;
}

OSERROR *event_finalise(void *privateWord)
{
  OSERROR *result=0;


  result=(OSERROR *) xosbyte(osbyte_DISABLE_EVENT,Event_KeyTransition,0);
  xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_VERYLOW,"event_finalise: disable eventv result=%p\n",result);
  result=(OSERROR *) xos_release(EventV,(void *) event_eventv_entry,privateWord);
  xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_VERYLOW,"event_finalise: release eventv result=%p\n",result);
/*  result=(OSERROR *) xos_release(MouseV,(void *) event_mousev_entry,privateWord); */

  return result;
}

