CC = gcc
CFLAGS = -Wall -Wextra -Werror
LDFLAGS = -lssl -lcrypto -lbsd

SRCDIR = src
OBJDIR = obj

SRCS = $(SRCDIR)/printers.c $(SRCDIR)/crypter.c $(SRCDIR)/decrypter.c $(SRCDIR)/main.c \
		$(SRCDIR)/base64.c
OBJS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

includes = src/stockholm.h

NAME = stockholm


all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@ 

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(includes) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all lib clean fclean re