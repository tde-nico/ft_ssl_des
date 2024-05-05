#ifndef FT_SSH_H
# define FT_SSH_H

# define _GNU_SOURCE
# include <stdlib.h>
# include <stdio.h>
# include <unistd.h>
# include <fcntl.h>
# include <sys/mman.h>

# define PROMPT "\033[35mft_ssl> \033[0m"
# define BSIZE 1024
# define HEX "0123456789abcdef"

# define PRINT_HEX(data, size) for (u_int32_t i = 0; i < size; ++i) { printf("%02x", data[i]); }
# define ROTLD(x, n) ((x << n) | (x >> (32 - n)))
# define ROTRD(x, n) ((x >> n) | (x << (32 - n)))
# define ROTLQ(x, n) ((x << n) | (x >> (64 - n)))
# define ROTRQ(x, n) ((x >> n) | (x << (64 - n)))
# define STORE_D_BIG(a, b) \
	((u_int8_t *)(b))[0] = ((u_int32_t)(a) >> 24) & 0xFFU, \
	((u_int8_t *)(b))[1] = ((u_int32_t)(a) >> 16) & 0xFFU, \
	((u_int8_t *)(b))[2] = ((u_int32_t)(a) >> 8) & 0xFFU, \
	((u_int8_t *)(b))[3] = ((u_int32_t)(a) >> 0) & 0xFFU
#define LOAD_D_BIG(a) \
	(((u_int32_t)(((u_int8_t *)(a))[0]) << 24) \
	| ((u_int32_t)(((u_int8_t *)(a))[1]) << 16) \
	| ((u_int32_t)(((u_int8_t *)(a))[2]) << 8) \
	| ((u_int32_t)(((u_int8_t *)(a))[3])))


typedef struct s_hash
{
	char		*name;
	void		(*init)(void);
	void		(*update)(u_int8_t *, size_t);
	void		(*final)(u_int8_t *);
	u_int32_t	digest_size;
	u_int32_t	block_size;
}	t_hash;

typedef struct s_sym_algo
{
	char		*name;
	u_int32_t	block_size;
	u_int32_t	key_size;
	void		(*init)(u_int8_t *, u_int32_t);
	void		(*encrypt)(u_int8_t *, u_int8_t *);
	void		(*decrypt)(u_int8_t *, u_int8_t *);
}	t_sym_algo;

typedef struct s_sym_mode_args
{
	int			in_fd;
	int			tmp_fd;
	int			out_fd;
	int			enc;
	int			b64;
	u_int8_t	*key;
	u_int8_t	*iv;
	u_int8_t	*salt;
	char		*passwd;
}	t_sym_mode_args;

typedef struct s_sym_mode
{
	char	*name;
	void	(*encrypt)(t_sym_algo *, t_sym_mode_args *);
	void	(*decrypt)(t_sym_algo *, t_sym_mode_args *);
}	t_sym_mode;

typedef struct s_sym
{
	t_sym_algo	algo;
	t_sym_mode	mode;
}	t_sym;

typedef struct s_cmd
{
	char	*name;
	int		(*schedule)(void *, int, char **);
	void	*algo;
}	t_cmd;


// hash.c
int			ft_hash(void *algo, int argc, char **argv);

// libft.c
size_t		ft_strlen(const char *str);
int			ft_strncmp(const char *s1, const char *s2, unsigned int n);
void		*ft_memset(void *b, int c, size_t len);
char		*ft_strchr(const char *s, int c);
void		*ft_memcpy(void *dst, const void *src, size_t n);

// padding.c
void		pad_pkcs5(u_int8_t *dst, u_int32_t len, u_int32_t block_size);
u_int32_t	unpad_pkcs5(u_int8_t *buf, u_int32_t len, u_int32_t block_size);

// pbkdf.c
int			key_gen(t_sym_mode_args *args, u_int32_t block_size);

// symmetric.c
int			ft_symmetric(void *algo, int argc, char **argv);

// utils.c
size_t		readb(int fd, u_int8_t *buf, size_t len);
u_int8_t	*bytes_from_hex(char *str, u_int32_t len);


#endif
