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

void *my_malloc(size_t size)
{
    void *ptr = malloc(size);

    if (ptr == NULL)
        exit(84);
    memset(ptr, 0, size);
    return (ptr);
}

void build_ip_header(iphdr_t *iphdr, size_t packet_len, struct sockaddr_in *sin)
{
    iphdr->ihl = sizeof(iphdr_t) / 4;
    iphdr->version = 4;
    iphdr->tos = 0;
    iphdr->tot_len = (uint16_t) packet_len;
    iphdr->id = (uint16_t) random();
    iphdr->frag_off = 0;
    iphdr->ttl = 42;
    iphdr->protocol = IPPROTO_UDP;
    iphdr->check = 0;
    iphdr->saddr = 0;
    iphdr->daddr = sin->sin_addr.s_addr;
}

void build_udp_header(udphdr_t *udphdr, struct sockaddr_in *sin, size_t size, uint16_t source_port)
{
    udphdr->uh_dport = sin->sin_port;
    udphdr->uh_sport = source_port;
    udphdr->uh_ulen = htons(sizeof(udphdr_t) + size);
    udphdr->uh_sum = 0;
}

void build_socket_addr(struct sockaddr_in *sin, uint16_t port, char *addr)
{
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = inet_addr(addr);
}

void *build_raw_udp_packet(udp_socket_t *this, udp_data_t *data)
{
    void *packet = my_malloc(sizeof(iphdr_t) + sizeof(udphdr_t) + data->size);
    iphdr_t *iphdr = packet;
    udphdr_t *udphdr = packet + sizeof(iphdr_t);
    void *data_addr = packet + sizeof(iphdr_t) + sizeof(udphdr_t);

    build_ip_header(iphdr, sizeof(iphdr_t) + sizeof(udphdr_t) + data->size, &(this->sin));
    build_udp_header(udphdr, &(this->sin), data->size, this->source_port);
    memcpy(data_addr, data->data, data->size);
    return (packet);
}

bool_t send_udp_socket(udp_socket_t *this, udp_data_t *data)
{
    void *packet;
    size_t packet_size = sizeof(iphdr_t) + sizeof(udphdr_t) + data->size;

    packet = build_raw_udp_packet(this, data);
    if (sendto(this->socket, packet, packet_size, 0, (struct sockaddr *) &(this->sin), sizeof(this->sin)) < 0) {
        perror("Error sendto()");
        return (false);
    }
    free(packet);
    return (true);
}

udp_data_t *receive_udp_socket(udp_socket_t *this)
{
    udp_data_t *res = my_malloc(sizeof(udp_socket_t));
    int readed = 0;
    size_t data_size = 0;

    res->data = my_malloc(4096);
    if ((readed = recvfrom(this->socket, res->data, 4096, MSG_WAITALL, NULL, NULL)) < 0) {
        perror("recv from error");
        free(res->data);
        free(res);
        return (NULL);
    }
    if (((udphdr_t *) (res->data + sizeof(iphdr_t)))->uh_sport == this->source_port) {
        free(res->data);
        free(res);
        return (receive_udp_socket(this));
    }
    data_size = readed - sizeof(iphdr_t) - sizeof(udphdr_t);
    memmove(res->data, res->data + sizeof(iphdr_t) + sizeof(udphdr_t), data_size);
    memset(res->data + data_size, 0, 4096 - data_size);
    res->size = readed - sizeof(iphdr_t) - sizeof(udphdr_t);
    return (res);
}

udp_socket_t *new_udp_socket(char *ip, uint16_t port)
{
    udp_socket_t *res = my_malloc(sizeof(udp_socket_t));
    int on = 1;
    uint16_t source_port = 0;

    build_socket_addr(&(res->sin), port, ip);
    res->socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    setsockopt(res->socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    while (source_port < 2048 && source_port != port)
        source_port = (uint16_t) random();
    res->source_port = htons(source_port);
    res->read = &receive_udp_socket;
    res->write = &send_udp_socket;
    return (res);
}

void delete_udp_socket(udp_socket_t *udp_socket)
{
    if (udp_socket == NULL || udp_socket->socket == -1)
        return;
    close(udp_socket->socket);
    free(udp_socket);
}

uint8_t *sha256_hash(void *data, size_t data_size)
{
    uint8_t *res = my_malloc(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, data_size);
    SHA256_Final(res, &ctx);
    return (res);
}

char *data_to_ascii_hex(void *data, size_t data_size)
{
    char *res = my_malloc((data_size * 2) + 1);

    for (size_t i = 0; i < data_size; i++)
        sprintf(&(res[i * 2]), "%02x", ((uint8_t *) data)[i]);
    return (res);
}

bool_t chap_client_challenge(udp_socket_t *udp_socket, udp_data_t *data, char *password)
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
    int n;

    if (chap_arg->target == NULL || chap_arg->port == 0 || chap_arg->password == NULL)
        return (false);
    n = getaddrinfo(chap_arg->target, chap_arg->string_port, &(struct addrinfo) { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, &result);
    if (n != 0) {
        printf("No such hostname: '%s'\n", chap_arg->target);
        return (false);
    }
    chap_arg->target = inet_ntoa(((struct sockaddr_in *) (result->ai_addr))->sin_addr);
    return (true);
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