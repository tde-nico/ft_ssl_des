#include "ft_ssl.h"
#include "md5.h"
#include "sha256.h"
#include "whirlpool.h"
#include "base64.h"
#include "symmetric.h"
#include "des.h"
#include "des3.h"


static t_hash	g_hash[] = {
	{"MD5", &md5_init, &md5_update, &md5_final, MD5_DIGEST_SIZE, MD5_BLOCK_SIZE},
	{"SHA256", &sha256_init, &sha256_update, &sha256_final, SHA256_DIGEST_SIZE, SHA256_BLOCK_SIZE},
	{"WHIRLPOOL", &whirlpool_init, &whirlpool_update, &whirlpool_final, WHIRLPOOL_DIGEST_SIZE, WHIRLPOOL_BLOCK_SIZE},
};

static t_sym	g_sym[] = {
	{{"des", DES_BLOCK_SIZE, DES_KEY_SIZE, &des_init, &des_encrypt, &des_decrypt}, {"ecb", &ecb_encrypt, &ecb_decrypt}},
	{{"des", DES_BLOCK_SIZE, DES_KEY_SIZE, &des_init, &des_encrypt, &des_decrypt}, {"cbc", &cbc_encrypt, &cbc_decrypt}},
	{{"des", DES_BLOCK_SIZE, DES_KEY_SIZE, &des_init, &des_encrypt, &des_decrypt}, {"pcbc", &pcbc_encrypt, &pcbc_decrypt}},
	{{"des", DES_BLOCK_SIZE, DES_KEY_SIZE, &des_init, &des_encrypt, &des_decrypt}, {"cfb", &cfb_encrypt, &cfb_decrypt}},
	{{"des", DES_BLOCK_SIZE, DES_KEY_SIZE, &des_init, &des_encrypt, &des_decrypt}, {"ofb", &ofb_encrypt, &ofb_decrypt}},
	{{"des", DES_BLOCK_SIZE, DES_KEY_SIZE, &des_init, &des_encrypt, &des_decrypt}, {"ctr", &ctr_encrypt, &ctr_decrypt}},
	{{"des3", DES3_BLOCK_SIZE, DES3_KEY_SIZE, &des3_init, &des3_encrypt, &des3_decrypt}, {"ecb", &ecb_encrypt, &ecb_decrypt}},
	{{"des3", DES3_BLOCK_SIZE, DES3_KEY_SIZE, &des3_init, &des3_encrypt, &des3_decrypt}, {"cbc", &cbc_encrypt, &cbc_decrypt}},
	{{"des3", DES3_BLOCK_SIZE, DES3_KEY_SIZE, &des3_init, &des3_encrypt, &des3_decrypt}, {"pcbc", &pcbc_encrypt, &pcbc_decrypt}},
	{{"des3", DES3_BLOCK_SIZE, DES3_KEY_SIZE, &des3_init, &des3_encrypt, &des3_decrypt}, {"cfb", &cfb_encrypt, &cfb_decrypt}},
	{{"des3", DES3_BLOCK_SIZE, DES3_KEY_SIZE, &des3_init, &des3_encrypt, &des3_decrypt}, {"ofb", &ofb_encrypt, &ofb_decrypt}},
	{{"des3", DES3_BLOCK_SIZE, DES3_KEY_SIZE, &des3_init, &des3_encrypt, &des3_decrypt}, {"ctr", &ctr_encrypt, &ctr_decrypt}},
};

static t_cmd	g_cmds[] = {
	{"md5", &ft_hash, &g_hash[0]},
	{"sha256", &ft_hash, &g_hash[1]},
	{"whirlpool", &ft_hash, &g_hash[2]},
	{"base64", &ft_base64, NULL},
	{"des-ecb", &ft_symmetric, &g_sym[0]},
	{"des-cbc", &ft_symmetric, &g_sym[1]},
	{"des-pcbc", &ft_symmetric, &g_sym[2]},
	{"des-cfb", &ft_symmetric, &g_sym[3]},
	{"des-ofb", &ft_symmetric, &g_sym[4]},
	{"des-ctr", &ft_symmetric, &g_sym[5]},
	{"des3-ecb", &ft_symmetric, &g_sym[6]},
	{"des3-cbc", &ft_symmetric, &g_sym[7]},
	{"des3-pcbc", &ft_symmetric, &g_sym[8]},
	{"des3-cfb", &ft_symmetric, &g_sym[9]},
	{"des3-ofb", &ft_symmetric, &g_sym[10]},
	{"des3-ctr", &ft_symmetric, &g_sym[11]},
	{NULL, NULL, NULL},
};


int	usage(void)
{
	int	i;

	printf("possible commands:\n");
	i = 0;
	while (g_cmds[i].name)
	{
		printf("\t%s\n", g_cmds[i].name);
		i++;
	}
	return (1);
}

int	ft_ssl(int argc, char **argv)
{
	int	i;

	if (argv[0] == NULL || argv[0][0] == '\0')
		return (0);
	i = 0;
	while (g_cmds[i].name)
	{
		if (!ft_strncmp(g_cmds[i].name, argv[0], ft_strlen(g_cmds[i].name)+1))
			return (g_cmds[i].schedule(g_cmds[i].algo, --argc, &argv[1]));
		i++;
	}
	return (1);
}

int	go_interactive(void)
{
	int		argc;
	int		prompt_len;
	char	buf[BSIZE];
	char	*argv[BSIZE];
	int		blen;
	int		i;
	int		is_start_word;

	prompt_len = ft_strlen(PROMPT);
	while (1)
	{
		i = -1;
		is_start_word = 1;
		argc = 0;
		write(1, PROMPT, prompt_len);
		blen = read(0, buf, BSIZE);
		if (blen <= 0)
			break ;
		buf[blen - 1] = '\0';
		if (!ft_strncmp(buf, "exit", 4) || !ft_strncmp(buf, "q", 1))
			break ;
		while (++i < blen-1)
		{
			if (buf[i] == ' ')
			{
				buf[i] = '\0';
				is_start_word = 1;
			}
			else if (is_start_word)
			{
				argv[argc++] = &buf[i];
				is_start_word = 0;
			}
		}
		argv[argc] = NULL;
		if (ft_ssl(argc, argv))
			usage();
	}
	write(1, "\n", 1);
	return (0);
}

int	main(int argc, char **argv)
{
	if (argc < 2)
		return (go_interactive());

	if (ft_ssl(argc-1, &argv[1]))
		return (usage());

	return (0);
}
