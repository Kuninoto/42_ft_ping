CC = cc
CFLAGS = -Wall -Wextra -Werror \
         -Wformat=2 -Wformat-security -Wformat-truncation \
         -fstack-protector-strong -pipe #-g -D DEBUG=1
LDFLAGS = -lm
INCLUDE = -I./src
RM = rm -rf

NAME = ft_ping

SRCS = dns.c icmp.c main.c network.c options.c output.c
OBJ_DIR = obj
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)

all: $(NAME)

$(NAME): $(OBJ_DIR) $(OBJS)
	$(info Linking $(NAME)...)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $(NAME)
	$(info Done!)
	$(info Usage: $(NAME) [options] <destination>)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: src/%.c
	$(info Compiling $<...)
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	$(RM) $(OBJ_DIR)

fclean: clean
	$(RM) $(NAME)

re: fclean all

test: $(NAME)
	sudo valgrind --leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--track-fds=yes \
		-s ./$(NAME) $(filter-out $@,$(MAKECMDGOALS))

# Prevent Make from throwing errors about targets that don't exist
# (which is what CLI arguments would look like to Make)
# this is needed to be able to run `make test <args>`
%:
	@:

.PHONY: all $(NAME) $(OBJ_DIR) clean fclean re test

.SILENT:
