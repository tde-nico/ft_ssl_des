#include "ft_ssl.h"
#include "base64.h"

int arg_parse(t_sym *sym, t_sym_mode_args *args, int argc, char **argv)
{
	u_int32_t	i;

	args->in_fd = STDIN_FILENO;
	args->out_fd = STDOUT_FILENO;
	args->tmp_fd = -1;
	args->enc = 1;
	args->b64 = 0;
	args->key = NULL;
	args->iv = NULL;
	args->salt = NULL;
	args->passwd = NULL;

	i = -1;
	while (++i < (unsigned int)argc)
	{
		if (!ft_strncmp(argv[i], "-i", 3))
		{
			if (argv[++i] == NULL)
				return (printf("Error: no input file\n"));
			args->in_fd = open(argv[i], O_RDONLY);
			if (args->in_fd < 0)
				return (printf("Error: open file (%s)\n", argv[i]));
		}
		else if (!ft_strncmp(argv[i], "-o", 3))
		{
			if (argv[++i] == NULL)
				return (printf("Error: no output file\n"));
			args->out_fd = open(argv[i], O_RDWR | O_CREAT);
			if (args->out_fd < 0)
				return (printf("Error: open file (%s)\n", argv[i]));
		}
		else if (!ft_strncmp(argv[i], "-k", 3))
		{
			if (argv[++i] == NULL)
				return (printf("Error: no key specified\n"));
			args->key = bytes_from_hex(argv[i], sym->algo.key_size);
			if (args->key == NULL)
				return (1);
		}
		else if (!ft_strncmp(argv[i], "-v", 3))
		{
			if (argv[++i] == NULL)
				return (printf("Error: no iv specified\n"));
			args->iv = bytes_from_hex(argv[i], sym->algo.block_size);
			if (args->iv == NULL)
				return (1);
		}
		else if (!ft_strncmp(argv[i], "-s", 3))
		{
			if (argv[++i] == NULL)
				return (printf("Error: no salt specified\n"));
			args->salt = bytes_from_hex(argv[i], sym->algo.block_size);
			if (args->salt == NULL)
				return (1);
		}
		else if (!ft_strncmp(argv[i], "-p", 3))
		{
			if (argv[++i] == NULL)
				return (printf("Error: no password specified\n"));
			args->passwd = argv[i];
		}
		else if (!ft_strncmp(argv[i], "-d", 3))
			args->enc = 0;
		else if (!ft_strncmp(argv[i], "-e", 3))
			args->enc = 1;
		else if (!ft_strncmp(argv[i], "-a", 3))
			args->b64 = 1;
		else
			return (printf("Error: invalid option %s\n", argv[i]));
	}

	return (0);
}

void	free_args(t_sym_mode_args *args)
{
	if (args->key)
		free(args->key);
	if (args->iv)
		free(args->iv);
	if (args->salt)
		free(args->salt);
	if (args->in_fd != STDIN_FILENO)
		close(args->in_fd);
	if (args->out_fd != STDOUT_FILENO)
		close(args->out_fd);
}

void	setup_base64(t_sym_mode_args *args)
{
	int	fd;

	if (!args->b64)
		return ;
	fd = memfd_create("tmp_fd", 0);
	if (args->enc)
	{
		args->tmp_fd = args->out_fd;
		args->out_fd = fd;
	}
	else
	{
		base64_decode(args->in_fd, fd);
		close(args->in_fd);
		lseek(fd, 0, SEEK_SET);
		args->in_fd = fd;
	}
}

void	teardown_base64(t_sym_mode_args *args)
{
	if (!args->b64 || !args->enc)
		return ;
	lseek(args->out_fd, 0, SEEK_SET);
	base64_encode(args->out_fd, args->tmp_fd);
}

int	ft_symmetric(void *algo, int argc, char **argv)
{
	t_sym			*sym;
	t_sym_mode_args	args;

	sym = (t_sym *)algo;
	if (arg_parse(sym, &args, argc, argv))
		return (1);

	setup_base64(&args);
	if (!key_gen(&args, sym->algo.block_size))
	{
		if (args.enc)
			sym->mode.encrypt(&sym->algo, &args);
		else
			sym->mode.decrypt(&sym->algo, &args);
	}
	teardown_base64(&args);

	free_args(&args);
	return (0);
}
