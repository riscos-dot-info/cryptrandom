#ifndef PUTTY_H
#define PUTTY_H

typedef unsigned int word32;

extern void SHATransform(word32 *digest, word32 *data);

extern int random_byte(void);
extern void random_add_noise(void *noise, int length);


#endif
