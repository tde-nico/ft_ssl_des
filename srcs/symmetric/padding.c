#include "ft_ssl.h"

void	pad_pkcs5(u_int8_t *dst, u_int32_t len, u_int32_t block_size)
{
	int	size;

	size = block_size - len;
	ft_memset(dst, size, size);
}

u_int32_t	unpad_pkcs5(u_int8_t *buf, u_int32_t len, u_int32_t block_size)
{
	u_int8_t	pad;
	u_int32_t	i;

	pad = buf[block_size - 1];
	i = -1;
	while (++i < pad)
	{
		if (buf[--len] != pad)
			return (block_size);
	}
	return (len);
}
