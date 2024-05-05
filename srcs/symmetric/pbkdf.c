#include "ft_ssl.h"
#include "sha256.h"
#include "hmac.h"

void	pbkdf2(t_hash *h, u_int8_t *p, u_int32_t p_len, u_int8_t *s,
	u_int32_t s_len, u_int32_t iters, u_int8_t *k, u_int32_t k_len)
{
	u_int32_t	i;
	u_int32_t	j;
	u_int32_t	w;
	u_int8_t	i_big[4] = {0};
	u_int8_t	tmp[HMAC_MAX_SIZE] = {0};
	u_int8_t	hdigest[HMAC_MAX_SIZE] = {0};

	i = 1;
	while (k_len > 0)
	{
		STORE_D_BIG(i, i_big);
		hmac_init(h, p, p_len);
		hmac_update(s, s_len);
		hmac_update(i_big, sizeof(i_big));
		hmac_final(hdigest);
		ft_memcpy(tmp, hdigest, h->digest_size);
		j = 0;
		while (++j < iters)
		{
			hmac_init(h, p, p_len);
			hmac_update(hdigest, h->digest_size);
			hmac_final(hdigest);
			w = -1;
			while (++w < h->digest_size)
				tmp[w] ^= hdigest[w];
		}
		if (k_len < h->digest_size)
			w = k_len;
		else
			w = h->digest_size;
		ft_memcpy(k, tmp, w);
		k += w;
		k_len -= w;
		++i;
	}
}

int	key_gen(t_sym_mode_args *args, u_int32_t block_size)
{
	t_hash		hash = {"SHA256", &sha256_init, &sha256_update, &sha256_final, SHA256_DIGEST_SIZE, SHA256_BLOCK_SIZE};
	u_int8_t	*key;

	if (args->key)
		return (0);
	if (!args->passwd || !args->salt)
		return (1);
	key = malloc(block_size);
	if (!key)
		return (printf("Error: malloc failed\n"));

	pbkdf2(
		&hash,
		(u_int8_t *)args->passwd,
		ft_strlen(args->passwd),
		args->salt,
		ft_strlen((char *)args->salt),
		10000,
		key,
		block_size
	);
	args->key = key;

	if (args->enc)
		dprintf(args->out_fd, "Salted__%s", args->salt);
	else
	{
		char	buf[8];

		ft_memset(buf, 0, sizeof(buf));
		read(args->in_fd, buf, sizeof(buf));
		if (!ft_strncmp(buf, "Salted__", 8))
			read(args->in_fd, buf, sizeof(buf));
		else
			lseek(args->in_fd, 0, SEEK_SET);
	}
	return (0);
}
