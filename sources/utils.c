/*
** EPITECH PROJECT, 2019
** NWP_mychap_2018
** File description:
** utils.c
*/

#include "mychap.h"

void *my_malloc(size_t size)
{
    void *ptr = malloc(size);

    if (ptr == NULL)
        exit(84);
    memset(ptr, 0, size);
    return (ptr);
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