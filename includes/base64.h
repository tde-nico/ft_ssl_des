#ifndef BASE64_H
# define BASE64_H

# include "ft_ssl.h"


int		ft_base64(void *algo, int argc, char **argv);
void	base64_encode(int in_fd, int out_fd);
void	base64_decode(int in_fd, int out_fd);


#endif
