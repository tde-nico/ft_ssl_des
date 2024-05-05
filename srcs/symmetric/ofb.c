#include "symmetric.h"

void	ofb_encrypt(t_sym_algo *algo, t_sym_mode_args *args)
{
	u_int8_t	*in;
	u_int8_t	*out;
	u_int8_t	*tmp;
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
	tmp = malloc(algo->block_size);
	if (!tmp) {
		free(out);
		free(in);
		return ;
	}

	algo->init(args->key, algo->key_size);
	while ((r = readb(args->in_fd, in, algo->block_size)) > 0)
	{
		algo->encrypt(args->iv, out);
		ft_memcpy(tmp, out, r);
		i = -1;
		while (++i < r)
			out[i] ^= in[i];
		write(args->out_fd, out, r);
		ft_memcpy(args->iv, args->iv + r, algo->block_size - r);
		ft_memcpy(args->iv + algo->block_size - r, tmp, r);
	}

	free(tmp);
	free(out);
	free(in);
}

void	ofb_decrypt(t_sym_algo *algo, t_sym_mode_args *args)
{
	ofb_encrypt(algo, args);
}
