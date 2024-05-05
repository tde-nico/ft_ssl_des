#ifndef DES3_H
# define DES3_H

#include "ft_ssl.h"
#include "des.h"

# define DES3_BLOCK_SIZE 8
# define DES3_KEY_SIZE 24

typedef struct s_des3_ctx
{
	u_int8_t	keys1[32];
	u_int8_t	keys2[32];
	u_int8_t	keys3[32];
}	t_des3_ctx;


void	des3_init(u_int8_t *key, u_int32_t len);
void	des3_encrypt(u_int8_t *in, u_int8_t *out);
void	des3_decrypt(u_int8_t *in, u_int8_t *out);


#endif
