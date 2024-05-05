#ifndef DES_H
# define DES_H

#include "ft_ssl.h"

# define DES_BLOCK_SIZE 8
# define DES_KEY_SIZE 8

# define SWAP_MOV_BIT(a, b, n, m) { \
	t = ((a >> n) ^ b) & m; \
	b ^= t; \
	a ^= t << n; \
}
# define KEY_PERM(c, d) { \
	SWAP_MOV_BIT(c, d, 4, 0x0F0F0F0F); \
	SWAP_MOV_BIT(c, d, 16, 0x0000FFFF); \
	SWAP_MOV_BIT(d, c, 2, 0x33333333); \
	SWAP_MOV_BIT(d, c, 8, 0x00FF00FF); \
	SWAP_MOV_BIT(c, d, 1, 0x55555555); \
	SWAP_MOV_BIT(d, c, 8, 0x00FF00FF); \
	SWAP_MOV_BIT(c, d, 16, 0x0000FFFF); \
	t = (c << 4) & 0x0FFFFFF0; \
	t |= (d >> 24) & 0x0000000F; \
	c = (d << 20) & 0x0FF00000; \
	c |= (d << 4) & 0x000FF000; \
	c |= (d >> 12) & 0x00000FF0; \
	c |= (d >> 28) & 0x0000000F; \
	d = t; \
}
# define ROL28(a, n) (((a << n) | (a >> (28 - n))) & 0x0FFFFFFF)
# define PERM_L(c, d) \
	(((c << 4) & 0x24000000) | \
	((c << 28) & 0x10000000) | \
	((c << 14) & 0x08000000) | \
	((c << 18) & 0x02080000) | \
	((c << 6) & 0x01000000) | \
	((c << 9) & 0x00200000) | \
	((c >> 1) & 0x00100000) | \
	((c << 10) & 0x00040000) | \
	((c << 2) & 0x00020000) | \
	((c >> 10) & 0x00010000) | \
	((d >> 13) & 0x00002000) | \
	((d >> 4) & 0x00001000) | \
	((d << 6) & 0x00000800) | \
	((d >> 1) & 0x00000400) | \
	((d >> 14) & 0x00000200) | \
	((d >> 0) & 0x00000100) | \
	((d >> 5) & 0x00000020) | \
	((d >> 10) & 0x00000010) | \
	((d >> 3) & 0x00000008) | \
	((d >> 18) & 0x00000004) | \
	((d >> 26) & 0x00000002) | \
	((d >> 24) & 0x00000001))
# define PERM_R(c, d) \
	(((c << 15) & 0x20000000) | \
	((c << 17) & 0x10000000) | \
	((c << 10) & 0x08000000) | \
	((c << 22) & 0x04000000) | \
	((c >> 2) & 0x02000000) | \
	((c << 1) & 0x01000000) | \
	((c << 16) & 0x00200000) | \
	((c << 11) & 0x00100000) | \
	((c << 3) & 0x00080000) | \
	((c >> 6) & 0x00040000) | \
	((c << 15) & 0x00020000) | \
	((c >> 4) & 0x00010000) | \
	((d >> 2) & 0x00002000) | \
	((d << 8) & 0x00001000) | \
	((d >> 14) & 0x00000808) | \
	((d >> 9) & 0x00000400) | \
	((d >> 0) & 0x00000200) | \
	((d << 7) & 0x00000100) | \
	((d >> 7) & 0x00000020) | \
	((d >> 3) & 0x00000011) | \
	((d << 2) & 0x00000004) | \
	((d >> 21) & 0x00000002))
# define IP(l, r) { \
	SWAP_MOV_BIT(l, r,  4, 0x0F0F0F0F); \
	SWAP_MOV_BIT(l, r, 16, 0x0000FFFF); \
	SWAP_MOV_BIT(r, l,  2, 0x33333333); \
	SWAP_MOV_BIT(r, l,  8, 0x00FF00FF); \
	SWAP_MOV_BIT(l, r,  1, 0x55555555); \
	l = ROTLD(l, 1); \
	r = ROTLD(r, 1); \
}
# define IP_INV(l, r) { \
	l = ROTRD(l, 1); \
	r = ROTRD(r, 1); \
	SWAP_MOV_BIT(l, r,  1, 0x55555555); \
	SWAP_MOV_BIT(r, l,  8, 0x00FF00FF); \
	SWAP_MOV_BIT(r, l,  2, 0x33333333); \
	SWAP_MOV_BIT(l, r, 16, 0x0000FFFF); \
	SWAP_MOV_BIT(l, r,  4, 0x0F0F0F0F); \
}
# define ROUND_SP(l, r, k1, k2) { \
	t = r ^ k1; \
	l ^= sp2[(t >> 24) & 0x3F]; \
	l ^= sp4[(t >> 16) & 0x3F]; \
	l ^= sp6[(t >> 8) & 0x3F]; \
	l ^= sp8[t & 0x3F]; \
	t = ROTRD(r, 4) ^ k2; \
	l ^= sp1[(t >> 24) & 0x3F]; \
	l ^= sp3[(t >> 16) & 0x3F]; \
	l ^= sp5[(t >> 8) & 0x3F]; \
	l ^= sp7[t & 0x3F]; \
}

typedef struct s_des_ctx
{
	u_int32_t	keys[32];
}	t_des_ctx;


void	des_init(u_int8_t *key, u_int32_t len);
void	des_encrypt(u_int8_t *in, u_int8_t *out);
void	des_decrypt(u_int8_t *in, u_int8_t *out);


#endif
