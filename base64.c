#include "base64.h"
#include <string.h>
#include <ctype.h>

static const char base64_table[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char base64_pad = '=';

int base64_encode(const unsigned char *input, size_t length, char *output) {
  int i = 0, j = 0;
  unsigned char a3[3] = {0};
  unsigned char a4[4] = {0};

  if (!input || length == 0) return -1;

  while (length--) {
    a3[i++] = *(input++);
    if (i == 3) {
      a4[0] = (a3[0] & 0xfc) >> 2;
      a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
      a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
      a4[3] = a3[2] & 0x3f;

      for (i = 0; i < 4; i++) {
        output[j++] = base64_table[a4[i]];
      }
      i = 0;
    }
  }

  if (i) {
    int k;
    for (k = i; k < 3; k++) {
      a3[k] = '\0';
    }

    a4[0] = (a3[0] & 0xfc) >> 2;
    a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
    a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
    a4[3] = a3[2] & 0x3f;

    for (k = 0; k < i + 1; k++) {
      output[j++] = base64_table[a4[k]];
    }

    while (i++ < 3) {
      output[j++] = base64_pad;
    }
  }

  output[j] = '\0';
  return 0;
}

static int is_base64(char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

static char base64_decode_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int base64_decode(const char *input, unsigned char *output) {
  int i = 0, j = 0;
  int in_len = 0;
  unsigned char a3[3] = {0};
  unsigned char a4[4] = {0};

  if (!input || (in_len = strlen(input)) == 0) return -1;

  while (in_len-- && (input[j] != base64_pad) && is_base64(input[j])) {
    a4[i++] = input[j++];
    if (i == 4) {
      for (i = 0; i < 4; i++) {
        a4[i] = base64_decode_value(a4[i]);
      }

      a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
      a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
      a3[2] = ((a4[2] & 0x3) << 6) + a4[3];

      for (i = 0; i < 3; i++) {
        output[j++] = a3[i];
      }
      i = 0;
    }
  }

  if (i) {
    int k;
    for (k = i; k < 4; k++) {
      a4[k] = 0;
    }

    for (k = 0; k < 4; k++) {
      a4[k] = base64_decode_value(a4[k]);
    }

    a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
    a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
    a3[2] = ((a4[2] & 0x3) << 6) + a4[3];

    for (k = 0; k < i - 1; k++) {
      output[j++] = a3[k];
    }
  }

  output[j] = '\0';

  return 0;
}
