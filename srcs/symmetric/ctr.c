#include "symmetric.h"

void	ctr_encrypt(t_sym_algo *algo, t_sym_mode_args *args)
{
	u_int8_t	*in;
	u_int8_t	*out;
	u_int32_t	r;
	u_int32_t	i;

	if (!args->key || !args->iv)
		return ;
	in = malloc(algo->block_size);
	if (!in)
		return ;
	out = malloc(algo->block_size);
	if (!out) {
		free(in);
		return ;
	}

	algo->init(args->key, algo->key_size);
	while ((r = readb(args->in_fd, in, algo->block_size)) > 0)
	{
		algo->encrypt(args->iv, out);
		i = -1;
		while (++i < algo->block_size)
			out[i] = in[i] ^ out[i];
		write(args->out_fd, out, r);
		i = -1;
		r = 1;
		while (++i <= algo->block_size)
		{
			r += args->iv[algo->block_size - i];
			args->iv[algo->block_size - i] = r & 0xFF;
			r >>= 8;
		}
	}

	free(out);
	free(in);
}

void	ctr_decrypt(t_sym_algo *algo, t_sym_mode_args *args)
{
	ctr_encrypt(algo, args);
}
