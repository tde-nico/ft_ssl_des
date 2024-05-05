#include "ft_ssl.h"

size_t	readb(int fd, u_int8_t *buf, size_t len)
{
	size_t	sum;
	size_t	r;

	sum = 0;
	while (sum < len)
	{
		r = read(fd, &buf[sum], 1);
		if (r <= 0)
			break ;
		++sum; 
	}
	return (sum);
}

u_int8_t	*bytes_from_hex(char *str, u_int32_t len)
{
	u_int8_t	*hex;
	u_int8_t	*out;
	u_int8_t	tmp[3];
	u_int32_t	i;

	hex = malloc(len * 2);
	if (!hex) {
		printf("Error: malloc failed\n");
		return (NULL);
	}
	ft_memset(hex, '0', len * 2);
	out = malloc(len);
	if (!out) {
		printf("Error: malloc failed\n");
		free(hex);
		return (NULL);
	}

	i = -1;
	while (str[++i])
		hex[i] = str[i];
	tmp[2] = '\0';
	i = -1;
	while (++i < len)
	{
		tmp[0] = hex[i * 2];
		tmp[1] = hex[i * 2 + 1];
		out[i] = strtol((char *)tmp, NULL, 16);
	}

	free(hex);
	return (out);
}
