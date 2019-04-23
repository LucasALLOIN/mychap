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

#endif //NWP_MYCHAP_2018_MYCHAP_H
