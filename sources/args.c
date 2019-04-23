/*
** EPITECH PROJECT, 2019
** NWP_mychap_2018
** File description:
** args.c
*/

#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "mychap.h"

const struct option long_options[] =
{
    {"target", required_argument, NULL, 't'},
    {"port", required_argument, NULL, 'p'},
    {"password", required_argument, NULL, 'P'},
    {NULL, 0, NULL, 0}
};

void parse_arg(int argc, char **argv, chap_arg_t *to_fill)
{
    int ch = 0;

    while ((ch = getopt_long(argc, argv, "t:p:P:", long_options, NULL)) != -1) {
        switch (ch) {
            case 't':
                to_fill->target = optarg;
                break;
            case 'p':
                to_fill->port = (uint16_t) atoi(optarg);
                to_fill->string_port = optarg;
                break;
            case 'P':
                to_fill->password = optarg;
                break;
        }
    }
}

bool_t check_arg(chap_arg_t *chap_arg)
{
    struct addrinfo *result;
    struct addrinfo tmp = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    int n;

    if (chap_arg->target == NULL || chap_arg->port == 0 ||
        chap_arg->password == NULL)
        return (false);
    n = getaddrinfo(chap_arg->target, chap_arg->string_port, &tmp, &result);
    if (n != 0) {
        printf("No such hostname: '%s'\n", chap_arg->target);
        return (false);
    }
    chap_arg->target = inet_ntoa(
    ((struct sockaddr_in *) (result->ai_addr))->sin_addr);
    return (true);
}