#include "stockholm.h"

int	is_ft_extension(const char *file_name)
{
	char *p = strrchr(file_name, '.');
	int i = 0;

	if (!p)
		return (0);
	while (p[i])
	{
		if (i++ == 3)
			return (0);
	}
	if (i != 3)
		return (0);
	if (p[1] != 'f' && p[2] != 't')
		return (0);
	return (1);
}


int	file_decryptage(int fd, char *path_file, const unsigned char *key, const bool silent)
{
	unsigned char	iv[16]; // 128 bits (taille standart pour AES)
	char			new_name[NAME_MAX + 1];


	int file_fd = openat(fd, path_file, O_RDWR);
	if (file_fd == -1)
		return (print_perror("openat", silent), 0);

	strlcpy(new_name, path_file, strlen(path_file) - 2);
	if (renameat(fd, path_file, fd, new_name) == -1)
		return (print_perror("renameat", silent), 0);
	
	unsigned char	in_buf[4096];
	unsigned char	out_buf[4096 + 16];
	int				out_len = 4096;
	int				bytes_read = 0;

	if ((bytes_read = read(file_fd, iv, sizeof(iv))) != sizeof(iv))
	{
		close(file_fd);
		return (print_error("File was not crypted", silent), 0);
	}

	long	read_pos = bytes_read;
	long	write_pos = 0;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
	    close(file_fd);
		return (print_error("Cannot init cipher ctx", silent), 0);
	}
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	while ((bytes_read = pread(file_fd, in_buf, sizeof(in_buf), read_pos)) > 0)
	{
        EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read);
        
        pwrite(file_fd, out_buf, out_len, write_pos);
        read_pos += bytes_read;
        write_pos += out_len;
    }

    EVP_DecryptFinal_ex(ctx, out_buf, &out_len);
    pwrite(file_fd, out_buf, out_len, write_pos);

    ftruncate(file_fd, write_pos + out_len);

    EVP_CIPHER_CTX_free(ctx);
    close(file_fd);
	return (1);
}


int	folder_decryptage(char *path_to_folder, const unsigned char *key, const bool silent)
{
	if (access(path_to_folder, R_OK | W_OK | X_OK) == -1)
	    return (printf_error(silent, "Access refused for %s\n", path_to_folder), 0);

	DIR	*rep = opendir(path_to_folder);
	struct dirent	*ent = NULL;
	size_t			size;

	if (rep != NULL)
	{
		int fd = dirfd(rep);
		if (fd == -1)
			return (closedir(rep), print_perror("dirfd", silent), 1);

		if (strlcat(path_to_folder, "/", PATH_MAX) > PATH_MAX)
			return (closedir(rep), printf_error(silent, "Path of directorie to long: %s\n", path_to_folder), 1);

		size = strlen(path_to_folder);

		// print_msg(silent, "\nOpen directorie %s\n", path_to_folder);

		while ((ent = readdir(rep)) != NULL)
		{
			if (!strncmp(".", ent->d_name, 1) || !strncmp("..", ent->d_name, 2))
				continue ;
			
			path_to_folder[size] = '\0';

			if (ent->d_type == DT_DIR)
			{
				if (strlcat(path_to_folder, ent->d_name, PATH_MAX) > PATH_MAX)
				{	
					printf_error(silent, "Path of directorie to long: %s\n", path_to_folder);
					continue ;
				}
				folder_decryptage(path_to_folder, key, silent);
				continue ;
			}
			else if (is_ft_extension(ent->d_name))
			{
				print_msg(silent, "\x1b[38;5;10mDecryptage \x1b[0mde %s%s\n", path_to_folder, ent->d_name);
				file_decryptage(fd, ent->d_name, key, silent);
			}
		}
	}
	else
		return (printf_error(silent, "Cannot open folder %s\n", path_to_folder), 1);
	closedir(rep);
	return (0);
}
