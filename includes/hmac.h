#ifndef HMAC_H
# define HMAC_H

# include "ft_ssl.h"

# define HMAC_MAX_SIZE 64
# define HMAC_IPAD 0x36
# define HMAC_OPAD 0x5C

typedef struct	s_hmac_ctx
{
	t_hash	*hash;
	u_int8_t	key[HMAC_MAX_SIZE];
	u_int8_t	digest[HMAC_MAX_SIZE];
}	t_hmac_ctx;


void	hmac_init(t_hash *hash, u_int8_t *key, u_int32_t key_len);
void	hmac_update(u_int8_t *data, size_t len);
void	hmac_final(u_int8_t *digest);


#endif
