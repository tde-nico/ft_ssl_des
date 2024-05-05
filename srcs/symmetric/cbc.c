#include "symmetric.h"

void	cbc_encrypt(t_sym_algo *algo, t_sym_mode_args *args)
{
	u_int8_t	*in;
	u_int8_t	*out;
	u_int32_t	r;
	u_int32_t	i;
	u_int8_t	pad;

	pad = 1;
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
		if (r < algo->block_size)
		{
			pad_pkcs5(&in[r], r, algo->block_size);
			pad = 0;
		}
		i = -1;
		while (++i < algo->block_size)
			out[i] = in[i] ^ args->iv[i];
		algo->encrypt(out, out);
		ft_memcpy(args->iv, out, algo->block_size);
		write(args->out_fd, out, algo->block_size);
	}
	if (pad)
	{
		pad_pkcs5(in, r, algo->block_size);
		i = -1;
		while (++i < algo->block_size)
			out[i] = in[i] ^ args->iv[i];
		algo->encrypt(out, out);
		write(args->out_fd, out, algo->block_size);
	}

	free(out);
	free(in);
}

void	cbc_decrypt(t_sym_algo *algo, t_sym_mode_args *args)
{
	u_int8_t	*in;
	u_int8_t	*out;
	u_int8_t	tmp[16] = {0};
	u_int32_t	r;
	u_int32_t	i;
	u_int32_t	size;

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
		ft_memcpy(tmp, in, algo->block_size);
		algo->decrypt(in, out);
		i = -1;
		while (++i < algo->block_size)
			out[i] ^= args->iv[i];
		size = unpad_pkcs5(out, r, algo->block_size);
		ft_memcpy(args->iv, tmp, algo->block_size);
		write(args->out_fd, out, size);
	}

	free(out);
	free(in);
}
