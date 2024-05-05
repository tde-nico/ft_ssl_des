#ifndef SYMMETRIC_H
# define SYMMETRIC_H

# include "ft_ssl.h"

// cbc.c
void	cbc_encrypt(t_sym_algo *algo, t_sym_mode_args *args);
void	cbc_decrypt(t_sym_algo *algo, t_sym_mode_args *args);

// ctr.c
void	cfb_encrypt(t_sym_algo *algo, t_sym_mode_args *args);
void	cfb_decrypt(t_sym_algo *algo, t_sym_mode_args *args);

// ctr.c
void	ctr_encrypt(t_sym_algo *algo, t_sym_mode_args *args);
void	ctr_decrypt(t_sym_algo *algo, t_sym_mode_args *args);

// ecb.c
void	ecb_encrypt(t_sym_algo *algo, t_sym_mode_args *args);
void	ecb_decrypt(t_sym_algo *algo, t_sym_mode_args *args);

// ofb.c
void	ofb_encrypt(t_sym_algo *algo, t_sym_mode_args *args);
void	ofb_decrypt(t_sym_algo *algo, t_sym_mode_args *args);

// pcbc.c
void	pcbc_encrypt(t_sym_algo *algo, t_sym_mode_args *args);
void	pcbc_decrypt(t_sym_algo *algo, t_sym_mode_args *args);

#endif
