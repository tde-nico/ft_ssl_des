#include "ft_ssl.h"

static u_int8_t b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void	base64_encode(int in_fd, int out_fd)
{
	u_int8_t	r;
	int			i;
	u_int32_t	in;
	u_int8_t	out;

	in = 0;
	while ((r = readb(in_fd, (u_int8_t *)&in, 3)) > 0)
	{
		in = __bswap_32(in) >> 8;
		i = -1;
		while (++i < 4)
		{
			if (r >= i)
				out = b64_table[(in & (0xFC0000 >> (i*6))) >> (18-(i*6))];
			else
				out = '=';
			write(out_fd, &out, 1);
		}
		in = 0;
	}
	write(out_fd, "\n", 1);
}

void	base64_decode(int in_fd, int out_fd)
{
	u_int8_t	r;
	u_int8_t	in[4] = {0};
	u_int8_t	tmp;
	u_int32_t	out;
	int			i;

	while ((r = readb(in_fd, in, 4)) > 0)
	{
		out = 0;
		i = -1;
		while (++i < 4)
		{
			if (in[i] == '=') {
				--r;
				continue ;
			}
			tmp = (u_int8_t *)ft_strchr((char *)b64_table, in[i]) - b64_table;
			out |= tmp << (18 - (i * 6));
		}
		i = -1;
		while (++i < 3 && i < (r-1))
		{
			tmp = ((0xFF0000 >> (i*8)) & out) >> (16-(i*8));
			write(out_fd, &tmp, 1);
		}
		ft_memset(in, 0, sizeof(in));
	}
}

int	ft_base64(void *algo, int argc, char **argv)
{
	int	i;
	int	flag;
	int	in_fd;
	int	out_fd;

	(void)algo;
	flag = -1;
	in_fd = STDIN_FILENO;
	out_fd = STDOUT_FILENO;
	i = -1;
	while (++i < argc)
	{
		if (!ft_strncmp(argv[i], "-i", 3))
		{
			if (argv[++i] == NULL)
				return (printf("Error: no input file\n"));
			in_fd = open(argv[i], O_RDONLY);
			if (in_fd < 0)
				return (printf("Error: open file (%s)\n", argv[i]));
		}
		else if (!ft_strncmp(argv[i], "-o", 3))
		{
			if (argv[++i] == NULL)
				return (printf("Error: no output file\n"));
			out_fd = open(argv[i], O_RDWR | O_CREAT);
			if (out_fd < 0)
				return (printf("Error: open file (%s)\n", argv[i]));
		}
		else if (!ft_strncmp(argv[i], "-e", 3))
		{
			if (flag == -1)
				flag = 0;
			else
				return (printf("Error: multiple encription/decription options\n"));
		}
		else if (!ft_strncmp(argv[i], "-d", 3))
		{
			if (flag == -1)
				flag = 1;
			else
				return (printf("Error: multiple encription/decription options\n"));
		}
		else
			return (printf("Error: invalid option %s\n", argv[i]));
	}

	if (flag == -1)
		return (printf("Error: no encription/decription option\n"));

	if (flag == 0)
		base64_encode(in_fd, out_fd);
	else
		base64_decode(in_fd, out_fd);

	if (in_fd != STDIN_FILENO)
		close(in_fd);
	if (out_fd != STDOUT_FILENO)
		close(out_fd);
	return (0);
}
