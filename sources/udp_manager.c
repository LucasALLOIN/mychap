/*
** EPITECH PROJECT, 2019
** NWP_mychap_2018
** File description:
** udp_manager.c
*/

#include "mychap.h"

void delete_udp_data(udp_data_t *udp_data)
{
    free(udp_data->data);
    free(udp_data);
}

bool_t send_udp_socket(udp_socket_t *this, udp_data_t *data)
{
    void *packet;
    size_t packet_size = sizeof(iphdr_t) + sizeof(udphdr_t) + data->size;

    packet = build_raw_udp_packet(this, data);
    if (sendto(this->socket, packet, packet_size,
    0, (struct sockaddr *) &(this->sin), sizeof(this->sin)) < 0) {
        perror("Error sendto()");
        return (false);
    }
    free(packet);
    return (true);
}

udp_data_t *receive_udp_socket(udp_socket_t *this)
{
    udp_data_t *res = my_malloc(sizeof(udp_socket_t));
    int len = 0;
    size_t d_size = 0;

    res->data = my_malloc(4096);
    if ((len = recvfrom(this->socket, res->data, 4096, 0, NULL, NULL)) < 0) {
        perror("recv from error");
        delete_udp_data(res);
        return (NULL);
    }
    if (((udphdr_t *)
    (res->data + sizeof(iphdr_t)))->uh_dport != this->source_port) {
        delete_udp_data(res);
        return (receive_udp_socket(this));
    }
    d_size = len - sizeof(iphdr_t) - sizeof(udphdr_t);
    memmove(res->data, res->data + sizeof(iphdr_t) + sizeof(udphdr_t), d_size);
    memset(res->data + d_size, 0, 4096 - d_size);
    res->size = len - sizeof(iphdr_t) - sizeof(udphdr_t);
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