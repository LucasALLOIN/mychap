/*
** EPITECH PROJECT, 2019
** NWP_mychap_2018
** File description:
** main.c
*/

#include <time.h>
#include <arpa/inet.h>
#include <zconf.h>
#include <getopt.h>
#include <netdb.h>
#include "mychap.h"

bool_t chap_client_challenge(udp_socket_t *udp_socket, udp_data_t *data,
char *password)
{
    size_t password_len = strlen(password);
    uint8_t data_to_hash[data->size + password_len];
    uint8_t *hashed_data;
    char *hashed_data_hex;
    udp_data_t data_to_send;

    memcpy(data_to_hash, data->data, data->size);
    memcpy(data_to_hash + data->size, password, password_len);
    hashed_data = sha256_hash(data_to_hash, data->size + password_len);
    hashed_data_hex = data_to_ascii_hex(hashed_data, SHA256_DIGEST_LENGTH);
    free(hashed_data);
    data_to_send.data = hashed_data_hex;
    data_to_send.size = strlen(hashed_data_hex);
    if (udp_socket->write(udp_socket, &data_to_send) == false) {
        free(hashed_data_hex);
        return (false);
    }
    free(hashed_data_hex);
    return (true);
}

char *chap_auth(udp_socket_t *udp_socket, char *password)
{
    udp_data_t hello_data = {.data = CHAP_HELLO, .size = strlen(CHAP_HELLO)};
    udp_data_t *recv_data = NULL;
    char *secret;

    if (udp_socket->write(udp_socket, &hello_data) == false)
        return (NULL);
    recv_data = udp_socket->read(udp_socket);
    if (recv_data->size != 10)
        return (NULL);
    else if (chap_client_challenge(udp_socket, recv_data, password) == false)
        return (NULL);
    free(recv_data->data);
    free(recv_data);
    recv_data = udp_socket->read(udp_socket);
    secret = recv_data->data;
    free(recv_data);
    return (secret);
}

int main(int argc, char **argv)
{
    udp_socket_t *udp_socket = NULL;
    chap_arg_t chap_arg = {0x00};
    char *secret;

    srandom(time(NULL));
    parse_arg(argc, argv, &chap_arg);
    if (check_arg(&chap_arg) == false)
        return (84);
    udp_socket = new_udp_socket(chap_arg.target, chap_arg.port);
    secret = chap_auth(udp_socket, chap_arg.password);
    if (secret == NULL || strcmp(secret, "KO") == 0)
        printf("KO\n");
    else
        printf("Secret: '%s'\n", secret);
    free(secret);
    delete_udp_socket(udp_socket);
    return (0);
}