#ifndef _BASE64_H
#define _BASE64_H

#include <stdint.h>
#include <stddef.h>

int base64_encode(const unsigned char *input, size_t length, char *output);
int base64_decode(const char *input, unsigned char *output);

#endif
