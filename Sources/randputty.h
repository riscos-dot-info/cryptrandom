#ifndef RANDPUTTY_H
#define RANDPUTTY_H

extern void random_add_noise(void *noise, int length);
extern void random_stir(void);
extern void random_init(void);
extern int random_byte(void);
extern unsigned int random_word(void);
extern void random_get_savedata(void **data, int *len);
extern void random_block(void *block, int blockSize);

#endif
