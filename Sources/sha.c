#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "kernel.h"

#include "def.h"
#include "sysstruc.h"

#include "vartypes.h"
#include "putty.h"

OSERROR noMemForMessage = { 0x815112, "Cannot allocate memory in RMA for message" };

OSERROR *sha_digest(int flags, void *message, int messageLength, int *digestOutput)
{
  unsigned char *digestInput=NULL;
  int digestInputBits = 0;
  int i=0,j=0;
  word32 digest[5], *digestInputWord;

  /* if flags bit 0 is set, write in place - requires 72 bytes scratch
     space after data
   */
  if ((flags & 1)==0)
  {
    digestInput = malloc(messageLength + ((512+64)/8));
    if (digestInput==NULL)
      return &noMemForMessage;
    memcpy(digestInput,message,messageLength);
  }
  else
  {
    digestInput = (unsigned char *)message;
  }

  digestInputBits = messageLength*8+64 /* reserve space for size */;


  /* Pad on initial 1 bit (and 7 0 bits as well) */
  digestInput[messageLength] = 0x80;
  digestInputBits +=8;

  /* pad with zeros to 512-64 = 448 bits */
  if ((digestInputBits % 512)>0)
  {
    for (i=0; i<(512-(digestInputBits % 512))/8; i++)
    {
      digestInput[messageLength+1+i] = 0x0;
    }
    digestInputBits +=(512-(digestInputBits % 512));
  }
  digestInputBits -=64; /* return space for size */

  /* write 64 bit length in big endian order */
  digestInput[digestInputBits/8] = 0x0;
  digestInput[(digestInputBits/8)+1] = 0x0;
  digestInput[(digestInputBits/8)+2] = 0x0;
  digestInput[(digestInputBits/8)+3] = 0x0;

  digestInput[(digestInputBits/8)+4] = ((messageLength*8) & 0xFF000000)>>24;
  digestInput[(digestInputBits/8)+5] = ((messageLength*8) & 0x00FF0000)>>16;
  digestInput[(digestInputBits/8)+6] = ((messageLength*8) & 0x0000FF00)>>8;
  digestInput[(digestInputBits/8)+7] = ((messageLength*8) & 0x000000FF)>>0;

  digestInputBits +=64;

  /*for (i=0; i<(digestInputBits/8); i+=4)
    printf("%d: %.2x%.2x%.2x%.2x \n",i,digestInput[i],digestInput[i+1],digestInput[i+2],digestInput[i+3]);*/

  /* The SHA-1 magic starting constants */
  digest[0] = 0x67452301;
  digest[1] = 0xEFCDAB89;
  digest[2] = 0x98BADCFE;
  digest[3] = 0x10325476;
  digest[4] = 0xC3D2E1F0;

  digestInputWord = (word32 *) digestInput;

  for (i=0; i<(digestInputBits/8)/4; i+=16)
  {
    SHATransform(digest,&(digestInputWord[i]));
    /*printf("%x %x %x %x %x\n",digest[0],digest[1],digest[2],digest[3],digest[4]);*/
  }

  /*printf("%x %x %x %x %x\n",digest[0],digest[1],digest[2],digest[3],digest[4]);*/

  memcpy(digestOutput,digest,5*sizeof(word32));

  if ((flags & 1)==0)
    free(digestInput);

  return NO_OSERROR;
}

#ifdef TEST
int main(void)
{
  char *input1="abc";
  char *input2="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  char input3[1000001];
  int i=0;

  for (i=0; i<250000; i++)
    ((int *)input3)[i]=0x61616161;

  sha_digest(input3,strlen(input3));
}
#endif
