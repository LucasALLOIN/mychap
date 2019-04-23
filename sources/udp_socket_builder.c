/*
** EPITECH PROJECT, 2019
** NWP_mychap_2018
** File description:
** udp_socket.c
*/

#include <arpa/inet.h>
#include "mychap.h"

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

void build_udp_header(udphdr_t *udphdr, struct sockaddr_in *sin, size_t size,
uint16_t source_port)
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
    size_t packet_len = sizeof(iphdr_t) + sizeof(udphdr_t) + data->size;
    void *packet = my_malloc(packet_len);
    iphdr_t *iphdr = packet;
    udphdr_t *udphdr = packet + sizeof(iphdr_t);
    void *data_addr = packet + sizeof(iphdr_t) + sizeof(udphdr_t);

    build_ip_header(iphdr, packet_len, &(this->sin));
    build_udp_header(udphdr, &(this->sin), data->size, this->source_port);
    memcpy(data_addr, data->data, data->size);
    return (packet);
}