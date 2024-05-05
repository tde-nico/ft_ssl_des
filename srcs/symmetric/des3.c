#include "des3.h"

static t_des3_ctx	ctx = {0};


void	des3_init(u_int8_t *key, u_int32_t len)
{
	ft_memcpy(ctx.keys1, key, len);
	ft_memcpy(ctx.keys2, key + 8, len);
	ft_memcpy(ctx.keys3, key + 16, len);
}

void	des3_encrypt(u_int8_t *in, u_int8_t *out)
{
	des_init(ctx.keys1, DES_KEY_SIZE);
	des_encrypt(in, out);
	des_init(ctx.keys2, DES_KEY_SIZE);
	des_decrypt(out, out);
	des_init(ctx.keys3, DES_KEY_SIZE);
	des_encrypt(out, out);
}

void	des3_decrypt(u_int8_t *in, u_int8_t *out)
{
	des_init(ctx.keys3, DES_KEY_SIZE);
	des_decrypt(in, out);
	des_init(ctx.keys2, DES_KEY_SIZE);
	des_encrypt(out, out);
	des_init(ctx.keys1, DES_KEY_SIZE);
	des_decrypt(out, out);
}
