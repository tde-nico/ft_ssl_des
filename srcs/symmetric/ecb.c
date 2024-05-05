#include "symmetric.h"

void	ecb_encrypt(t_sym_algo *algo, t_sym_mode_args *args)
{
	u_int8_t	*in;
	u_int8_t	*out;
	u_int32_t	r;
	u_int8_t	pad;

	pad = 1;
	if (!args->key)
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
		if (r < algo->block_size)
		{
			pad_pkcs5(&in[r], r, algo->block_size);
			pad = 0;
		}
		algo->encrypt(in, out);
		write(args->out_fd, out, algo->block_size);
	}
	if (pad)
	{
		pad_pkcs5(in, r, algo->block_size);
		algo->encrypt(in, out);
		write(args->out_fd, out, algo->block_size);
	}

	free(out);
	free(in);
}

void	ecb_decrypt(t_sym_algo *algo, t_sym_mode_args *args)
{
	u_int8_t	*in;
	u_int8_t	*out;
	u_int32_t	r;
	u_int32_t	size;

	if (!args->key)
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
		algo->decrypt(in, out);
		size = unpad_pkcs5(out, r, algo->block_size);
		write(args->out_fd, out, size);
	}
	
	free(out);
	free(in);
}
