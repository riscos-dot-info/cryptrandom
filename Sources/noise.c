#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "kernel.h"

#include "os.h"
#include "osbyte.h"
#include "osreadsysinfo.h"
#include "wimpreadsysinfo.h"
#include "taskmanager.h"
#include "osfscontrol.h"
#include "osgbpb.h"
#include "portable.h"
#include "osword.h"
#include "osfile.h"
#include "osfind.h"
#include "osargs.h"
#include "fileswitch.h"
#include "osword.h"

#include "def.h"
#include "vartypes.h"
#include "macros.h"
#include "sysstruc.h"
#include "error.h"
#include "syslogif.h"
#include "randputty.h"

/* values from INKEY(-256) */
#define RISC_OS_350 0xA5
#define RISC_OS_360 0xA6

static bool noise_fexist(char *name)
{
  OSERROR *result=0;
  uint32 junk=0;
  fileswitch_object_type type=fileswitch_NOT_FOUND;

  result=(OSERROR *) xosfile_read_path(name,"",&type,
                           (bits *) &junk,
                           (bits *) &junk,
                           (int *)  &junk,
                           (fileswitch_attr *) &junk);
  if ((result) || (type==fileswitch_NOT_FOUND))
    return FALSE;
  else
    return TRUE;
}

static OSERROR *noise_load_seed(void)
{
  OSERROR *result;
  char fname[FILENAME_SIZE];
  byte *buffer;
  os_f fh;
  uint32 unread=0;
  osbool eof;

  buffer=malloc(1024*sizeof(byte));
  if (!buffer)
    return ERROR_OUTOFMEMORY;

  if (noise_fexist("<CryptRandom$SeedFile>"))
    strcpy(fname,"<CryptRandom$SeedFile>");
  else
    if (noise_fexist("Choices:Crypto.CryptRand.Seed"))
      strcpy(fname,"Choices:Crypto.CryptRand.Seed");
    else
      if (noise_fexist("<Wimp$ScrapDir>.CryptRand"))
        strcpy(fname,"<Wimp$ScrapDir>.CryptRand");
      else
      {
        free(buffer);
        return 0; /* no file to load */
      }

  result=(OSERROR *) xosfind_openin(osfind_NO_PATH,fname,"",&fh);
  if (!result)
  {
    do
    {
      result=(OSERROR *) xosgbpb_read(fh,buffer,1024,(int *) &unread);
      xsyslog_logdata(SYSLOG_FILE,LOG_DEBUG_VERYLOW,buffer,1024-unread,0);
      random_add_noise(buffer,1024-unread);
      xosargs_read_eof_status(fh,&eof);
    }
    while ((!result) && (!eof));
    xosfind_close(fh);
  }

  free(buffer);
  return REPORT(result);
}

void noise_save_seed(void)
{
  OSERROR *result=0;
  void *data=NULL;
  uint32 len=0,junk=0;
  char fname[FILENAME_SIZE];
  os_var_type type;

  result=(OSERROR *) xos_read_var_val("CryptRandom$SeedFile",fname,FILENAME_SIZE,0,3, /* expand macros */
                          (int *) &len,
                          (int *) &junk,
                                  &type);
  /* if no error, and not code and not number... */
  if ((!result) && (!(type>os_VARTYPE_CODE)) && (type!=os_VARTYPE_NUMBER))
  {
    strcpy(fname,"<CryptRandom$SeedFile>");
    xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_LOW,"noise_save_seed: using sv %s",fname);
  }
  else
  {
    if (noise_fexist("<Choices$Write>"))
    {
      if (!noise_fexist("<Choices$Write>.Crypto"))
      {
        result=(OSERROR *) xosfile_create_dir("<Choices$Write>.Crypto",0);
      }
      if (!noise_fexist("<Choices$Write>.Crypto.CryptRand"))
      {
        result=(OSERROR *) xosfile_create_dir("<Choices$Write>.Crypto.CryptRand",0);
      }
      strcpy(fname,"<Choices$Write>.Crypto.CryptRand.Seed");
      xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_LOW,"noise_save_seed: using ch %s",fname);
    }
    else
    {
      /* don't have CryptRandom$SeedFile or Choices: -
       * last resort...
       */
      strcpy(fname,"<Wimp$ScrapDir>.CryptRand");
      xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_LOW,"noise_save_seed: using ws %s",fname);
    }
  }

  xsyslog_irq_logf(SYSLOG_FILE,LOG_DEBUG_LOW,"noise_save_seed: saving to %s",fname);
  random_get_savedata(&data,(int *) &len);
  xosfile_save_stamped(fname,0xffd,(byte *) data,(byte *) data+len);
}

static void noise_add_string(void (*add) (void *, int), char *string)
{
  /* sanity check name in case something went wrong - if
     sensible length then add in */
  if (strlen(string)<256)
    add(string,strlen((char *) string));

}

/* add in a directory listing of directory <dir>, or if <getRoot> set
 * use it's root
 */
static void noise_add_dir_list(void (*add) (void *, int), char *dir,bool getRoot)
{
  OSERROR *result=0;
  char *bufferC=0,*dollarPos=0;
  osgbpb_system_info_list *infoList;
  uint32 item=0,readOut=0,junk=0;
  uint32 bufferSize=FILENAME_SIZE;
  uint32 infoListSize=FILENAME_SIZE+100;

  infoList=(osgbpb_system_info_list *) malloc(infoListSize);
  if (!infoList)
    return;
  bufferC=(char *) malloc(bufferSize);
  if (!bufferC)
    return;

  /* Expand dir into full path */
  result=(OSERROR *) xosfscontrol_canonicalise_path(dir,bufferC,0,0,
                                 bufferSize,(int *) &junk);
  if (result)
  {
    REPORT(result);
    free(infoList);
    free(bufferC);
    return;
  }
  /* if we want the root, try to terminate at the root */
  if (getRoot)
  {
    if ((dollarPos=strchr(bufferC,'$'))!=0)
    {
      /* terminate string at $ */
      dollarPos[1]='\0';
    }
  }

  item=0;

  do
  {
    result=(OSERROR *) xosgbpb_dir_entries_system_info(bufferC,infoList,1,
                                    item,infoListSize,"*",
                                    (int *) &readOut, (int *) &item);
    if (result)
    {
      REPORT(result);
      free(infoList);
      free(bufferC);
      return;
    }

    if (readOut>0)
    {
      add(&(infoList->info[0]),sizeof(osgbpb_SYSTEM_INFO(1))+strlen(infoList->info[0].name));
    }
  }
  while (item!=-1);

  free(infoList);
  free(bufferC);
}

/* noise_read_bmu_variable: _very_ silly function to prise lots of data
 * out of A4s battery manager.  This is silly because most A4s don't have
 * a network, but never mind!
 */

static uint32 noise_read_bmu_variable(uint32 variable)
{
  uint32 value;
  xportable_read_bmu_variable((portable_bmu_variable) variable,(int *) &value);

  return value;
}

/* noise_get_heavy: do lots of silly things to attempt to get 'random' data
 * to add the hasher with
 */

void noise_get_heavy(void (*add) (void *, int))
{
  OSERROR *result=0;
  uint32 buffer[128]; /* 128*sizeof(uint32) */
  uint32 junk;
  int tmContext=0;
  uint32 *bufferEnd=0;
  uint32 osVersion=0;
  os_dynamic_area_no dynArea=-1;
  uint32 i=0;
  SYSLOG_ENTRY("noise_get_heavy");

  xosbyte1(osbyte_IN_KEY,0,0xff /* -256 */,(int *) &osVersion);


  /* get machine ID - not random, but can't guess this easily */
  xosreadsysinfo_machine_id((osreadsysinfo_flags0 *) &junk,
                           (osreadsysinfo_flags1 *) &junk,
                           (osreadsysinfo_flags2 *) &junk,
                           (bits *) &(buffer[0]),
                           (bits *) &(buffer[1]));

  /* Number of running Wimp tasks */
  xwimpreadsysinfo_task_count((int *) &(buffer[2]));

  add(buffer,sizeof(uint32)*3);

  /* Read info on currently running tasks */
  tmContext=0;
  do
  {
    xtaskmanager_enumerate_tasks(tmContext,
                                 (taskmanager_task *) buffer,
                                 sizeof(buffer),
                                 &tmContext,
                                 (char **) &bufferEnd);
    /* add the info block in */
    add(buffer,bufferEnd-buffer);

    /* add their names in */
    for (i=0; i<((bufferEnd-buffer)/4); i++)
      noise_add_string(add,(char *) (buffer[(i*4)+1]));
  }
  while (tmContext>=0);

  /* and on current dynamic areas (only past RISC OS 3.5) */
  if (osVersion >= RISC_OS_350)
  {
    dynArea = (os_dynamic_area_no) -1;
    do
    {
      result=(OSERROR *) xosdynamicarea_enumerate((int) dynArea, (int *) &dynArea);
      if (result)
      {
        REPORT(result);
        break;
      }
      if (dynArea!=(os_dynamic_area_no) -1)
      {
        result=(OSERROR *) xosdynamicarea_read(dynArea,
                            (int *)   &(buffer[0]),  /* size */
                            (byte **) &(buffer[1]),  /* base address */
                            (bits *)  &(buffer[2]),  /* flags */
                            (int *)   &(buffer[3]),  /* max size */
                            (void **) &(buffer[4]),  /* handler */
                            (void **) &(buffer[5]),  /* handler ws */
                            (char **) &(buffer[6])); /* name */
        if (result)
        {
          REPORT(result);
          break;
        }
        /* add in area name */
        noise_add_string(add,(char *) buffer[6]);

        /* add in results of call */
        add(buffer,sizeof(uint32)*7);
      }
    }
    while (dynArea!=(os_dynamic_area_no)-1);
  }

  /* add in free space of disc containing Obey$Dir - this is the most likely
   * to be spinning (or use OS_Args 254 to get open files - but get devices
   * etc?)
   */
  if (osVersion<RISC_OS_360)
  {
    xosfscontrol_free_space("<Obey$Dir>",
                            (int *) &(buffer[0]),
                            (int *) &(buffer[1]),
                            (int *) &(buffer[2]));
    add(buffer,sizeof(uint32)*3);
  }
  else
  {
    xosfscontrol_free_space64("<Obey$Dir>",
                              (bits *) &(buffer[0]),
                              (int *) &(buffer[1]),
                              (int *) &(buffer[2]),
                              (bits *) &(buffer[3]),
                              (bits *) &(buffer[4]));
    add(buffer,sizeof(uint32)*5);
  }

  noise_add_dir_list(add,"<Obey$Dir>",TRUE);
  noise_add_dir_list(add,"<Wimp$ScrapDir>",FALSE);

  noise_load_seed();
  SYSLOG_EXIT("noise_get_heavy");
}

void noise_get_light(void (*add) (void *, int))
{
  uint32 buffer[16];
  uint32 i=0;
  SYSLOG_ENTRY("noise_get_light");

  /* add in the OS interval timer and RTC */

  /* buffer[1]=0; * since only write 5 bytes of time *
     buffer[3]=0; * we could clear bytes not being set - but does it matter?    */
  xosword_read_system_clock((osword_timer_block *) &(buffer[0]));
  /* OS_Word 14,3 - need to put reason code in buffer */
  buffer[2]=oswordreadclock_OP_UTC;
  xoswordreadclock_utc((oswordreadclock_utc_block *) &(buffer[2]));

  /* add in the battery status */
  for (i=0; i<12; i++)
  {
    buffer[4+i]=noise_read_bmu_variable(i);
  }

  add(buffer,sizeof(uint32)*16);

  SYSLOG_EXIT("noise_get_light");
}

void noise_get_ultralight(void (*add) (void *, int),void *data,uint32 size)
{
  uint32 time;
  uint32 buffer[4];
  oswordpointer_position_block ptrPos;

  add(data,size);
#if 0
  /* read the _buffered_ mouse position - this will lose entries from
   * the mouse queue on slow machines */
  xos_mouse((int *)  &(buffer[0]),
            (int *)  &(buffer[1]),
            (bits *) &(buffer[2]),
            (os_t *) &(buffer[3]));
  add(buffer,sizeof(uint32)*4);
#else
  /* read unbuffered position */
  ptrPos.op = oswordpointer_OP_READ_POSITION;
  xoswordpointer_read_position(&ptrPos);
  buffer[0] = ptrPos.x | (ptrPos.y<<16);
  add(buffer,sizeof(uint32));
#endif

  xos_read_monotonic_time((int *) &time);
  add(&time,sizeof(time));


}
