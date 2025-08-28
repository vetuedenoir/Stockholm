#include "stockholm.h"

int	ft_putstr_fd(const char *str, int fd)
{
	return (write(fd, str, strlen(str)));
}

void	print_msg(const bool silent, const char *fmt, ...)
{
	if (silent)
		return ;
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void	print_error(const char *msg, const bool silent)
{
	if (silent)
		return ;
	fprintf(stderr, "\x1b[31mERROR: \x1b[0m%s\n", msg);
}

void	printf_error(const bool silent, const char *fmt, ...)
{
	if (silent)
		return ;
	fprintf(stderr, "\x1b[31mERROR: \x1b[0m");
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

}

void	print_perror(const char *msg, const bool silent)
{
	if (silent)
		return ;
	ft_putstr_fd("\x1b[31mERROR: \x1b[0m", 2);
	perror(msg);
}