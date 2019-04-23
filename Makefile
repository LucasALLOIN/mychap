##
## EPITECH PROJECT, 2017
## Makefile
## File description:
## desc
##

CC	=	gcc

SRC	=	sources/main.c 					\
		sources/args.c 					\
		sources/udp_manager.c 			\
		sources/udp_socket_builder.c 	\
		sources/utils.c

CFLAGS	=	-I./includes/ -Werror -Wextra -W -Wall -Wparentheses -Wsign-compare -Wpointer-sign -Wuninitialized -Wunused-but-set-variable -g

OBJ	=	$(SRC:.c=.o)

NAME	=	client


all:	$(NAME)

$(NAME):	$(OBJ)
	@$(CC) -o $(NAME) -lcrypto $(OBJ)

clean:
	rm -f $(OBJ)

fclean:	clean
	rm -f $(NAME)

docker:
	sudo docker run -it -v `pwd`:/home/epitest -w /home/epitest epitechcontent/epitest-docker /bin/bash

re:	fclean all
