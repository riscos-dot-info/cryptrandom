#ifndef NOISE_H
#define NOISE_H

extern void noise_get_heavy(void (*stir) (void *, int));
extern void noise_get_light(void (*stir) (void *, int));
extern void noise_get_ultralight(void (*stir) (void *, int),void *data,uint32 size);
extern void noise_save_seed(void);

#endif
