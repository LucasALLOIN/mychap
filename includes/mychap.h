/*
** EPITECH PROJECT, 2019
** NWP_mychap_2018
** File description:
** mychap.h
*/

#ifndef NWP_MYCHAP_2018_MYCHAP_H
#define NWP_MYCHAP_2018_MYCHAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>

typedef enum bool_e {
    true,
    false
} bool_t;

typedef struct udp_data_s {
    void *data;
    size_t size;
} udp_data_t;

typedef struct udp_socket_s {
    int socket;
    struct sockaddr_in sin;
    uint16_t source_port;
    bool_t (*write)(struct udp_socket_s *, udp_data_t *);
    udp_data_t *(*read)(struct udp_socket_s *);
} udp_socket_t;

typedef struct chap_arg_s {
    char *password;
    uint16_t port;
    char *string_port;
    char *target;
} chap_arg_t;

typedef struct iphdr iphdr_t;
typedef struct udphdr udphdr_t;

#define CHAP_HELLO "client hello"

void *my_malloc(size_t size);
void delete_udp_data(udp_data_t *udp_data);
void build_ip_header(iphdr_t *iphdr, size_t packet_len, struct sockaddr_in *);
void build_udp_header(udphdr_t *udphdr, struct sockaddr_in *sin, size_t size,
uint16_t source_port);
void build_socket_addr(struct sockaddr_in *sin, uint16_t port, char *addr);
void *build_raw_udp_packet(udp_socket_t *this, udp_data_t *data);
bool_t send_udp_socket(udp_socket_t *this, udp_data_t *data);
udp_data_t *receive_udp_socket(udp_socket_t *this);
udp_socket_t *new_udp_socket(char *ip, uint16_t port);
void delete_udp_socket(udp_socket_t *udp_socket);
uint8_t *sha256_hash(void *data, size_t data_size);
char *data_to_ascii_hex(void *data, size_t data_size);
bool_t chap_client_challenge(udp_socket_t *udp_socket, udp_data_t *data,
char *password);
char *chap_auth(udp_socket_t *udp_socket, char *password);
void parse_arg(int argc, char **argv, chap_arg_t *to_fill);
bool_t check_arg(chap_arg_t *chap_arg);

#endif //NWP_MYCHAP_2018_MYCHAP_H
