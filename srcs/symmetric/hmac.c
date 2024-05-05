#include "hmac.h"

static t_hmac_ctx	ctx = {0};


void	hmac_init(t_hash *hash, u_int8_t *key, u_int32_t key_len)
{
	u_int32_t	i;

	ctx.hash = hash;
	if (key_len > hash->block_size)
	{
		hash->init();
		hash->update(key, key_len);
		hash->final(ctx.key);
	}
	else
		ft_memcpy(ctx.key, key, key_len);
	i = -1;
	while (++i < hash->block_size)
		ctx.key[i] ^= HMAC_IPAD;
	hash->init();
	hash->update(ctx.key, hash->block_size);
}

void	hmac_update(u_int8_t *data, size_t len)
{
	ctx.hash->update(data, len);
}

void	hmac_final(u_int8_t *digest)
{
	u_int32_t	i;

	ctx.hash->final(ctx.digest);
	i = -1;
	while (++i < ctx.hash->block_size)
		ctx.key[i] ^= HMAC_IPAD ^ HMAC_OPAD;
	ctx.hash->init();
	ctx.hash->update(ctx.key, ctx.hash->block_size);
	ctx.hash->update(ctx.digest, ctx.hash->digest_size);
	ctx.hash->final(digest);
	ft_memset(&ctx, 0, sizeof(ctx));
}
