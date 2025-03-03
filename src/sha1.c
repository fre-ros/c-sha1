#include "sha1.h"

#include <string.h>
#include <stdlib.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define LROTATE(n, r) (((n) << (r)) | ((n) >> (32U - (r))))

#define UNPACK_U32_BE(arr, i) (((uint32_t)(arr)[(i)]    << 24U) | \
                               ((uint32_t)(arr)[(i)+1U] << 16U) | \
                               ((uint32_t)(arr)[(i)+2U] << 8U)  | \
                               ((uint32_t)(arr)[(i)+3U] << 0U))

#define PACK_U32_BE(arr, i, u32) do \
  { \
    (arr)[(i)+0U] = ((u32) >> 24U) & 0xFFU; \
    (arr)[(i)+1U] = ((u32) >> 16U) & 0xFFU; \
    (arr)[(i)+2U] = ((u32) >> 8U)  & 0xFFU; \
    (arr)[(i)+3U] = ((u32) >> 0U)  & 0xFFU; \
  } while (0)


static const uint8_t zero_padding[64U] = {0U};

static void process(sha1_ctx *ctx)
{
  uint32_t w[80U] =
  {
    [0U]  = UNPACK_U32_BE(ctx->chunk, 0U),
    [1U]  = UNPACK_U32_BE(ctx->chunk, 4U),
    [2U]  = UNPACK_U32_BE(ctx->chunk, 8U),
    [3U]  = UNPACK_U32_BE(ctx->chunk, 12U),
    [4U]  = UNPACK_U32_BE(ctx->chunk, 16U),
    [5U]  = UNPACK_U32_BE(ctx->chunk, 20U),
    [6U]  = UNPACK_U32_BE(ctx->chunk, 24U),
    [7U]  = UNPACK_U32_BE(ctx->chunk, 28U),
    [8U]  = UNPACK_U32_BE(ctx->chunk, 32U),
    [9U]  = UNPACK_U32_BE(ctx->chunk, 36U),
    [10U] = UNPACK_U32_BE(ctx->chunk, 40U),
    [11U] = UNPACK_U32_BE(ctx->chunk, 44U),
    [12U] = UNPACK_U32_BE(ctx->chunk, 48U),
    [13U] = UNPACK_U32_BE(ctx->chunk, 52U),
    [14U] = UNPACK_U32_BE(ctx->chunk, 56U),
    [15U] = UNPACK_U32_BE(ctx->chunk, 60U)
  };

  for (size_t i = 16U; i < 80U; i++)
  {
    uint32_t rotate_temp = w[i-3U] ^ w[i-8U] ^ w[i-14U] ^ w[i-16U];
    w[i] = LROTATE(rotate_temp, 1U);
  }

  uint32_t a = ctx->h[0U];
  uint32_t b = ctx->h[1U];
  uint32_t c = ctx->h[2U];
  uint32_t d = ctx->h[3U];
  uint32_t e = ctx->h[4U];

  uint32_t f;
  uint32_t k;
  uint32_t temp;

  for (size_t i = 0U; i < 80U; i++)
  {
    if (i <= 19U)
    {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999U;
    }
    else if (i <= 39U)
    {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1U;
    }
    else if (i <= 59U)
    {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDCU;
    }
    else
    {
      f = b ^ c ^ d;
      k = 0xCA62C1D6U;
    }

    temp = LROTATE(a, 5U) + f + e + k + w[i];
    e = d;
    d = c;
    c = LROTATE(b, 30U);
    b = a;
    a = temp;
  }

  ctx->h[0U] += a;
  ctx->h[1U] += b;
  ctx->h[2U] += c;
  ctx->h[3U] += d;
  ctx->h[4U] += e;

  ctx->chunk_idx = 0U;
}

static char nibble_to_hex_char(uint8_t nibble)
{
  return "0123456789abcdef"[nibble & 0xFU];
}

void sha1(const uint8_t *data, size_t size, uint8_t result[static 20U])
{
  sha1_ctx ctx;
  sha1_init(&ctx);
  sha1_process(&ctx, data, size);
  sha1_finalize(&ctx, result);
}

void sha1_init(sha1_ctx *ctx)
{
  ctx->msg_len = 0U;
  ctx->chunk_idx = 0U;

  ctx->h[0U] = 0x67452301U;
  ctx->h[1U] = 0xefcdab89U;
  ctx->h[2U] = 0x98badcfeU;
  ctx->h[3U] = 0x10325476U;
  ctx->h[4U] = 0xc3d2e1f0U;
}

void sha1_process(sha1_ctx *ctx, const uint8_t *data, size_t size)
{
  uint32_t length_to_feed;
  uint32_t data_idx = 0U;

  ctx->msg_len += size;

  while (size > 0U)
  {
    length_to_feed = MIN(size, 64U - ctx->chunk_idx);
    memcpy(&ctx->chunk[ctx->chunk_idx], &data[data_idx], length_to_feed);

    size -= length_to_feed;
    data_idx += length_to_feed;
    ctx->chunk_idx += length_to_feed;

    if (ctx->chunk_idx == 64U)
    {
      process(ctx);
    }
  }
}

void sha1_finalize(sha1_ctx *ctx, uint8_t result[static 20U])
{
  uint64_t data_bit_length = ctx->msg_len * 8U;

  uint8_t one_bit_padding = 0x80U;
  sha1_process(ctx, &one_bit_padding, 1U);

  size_t padding_length = (ctx->chunk_idx > 56U) ? (56U + 64U - ctx->chunk_idx) : (56U - ctx->chunk_idx);
  sha1_process(ctx, zero_padding, padding_length);

  uint8_t data_bit_length_be_bytes[8U];
  PACK_U32_BE(data_bit_length_be_bytes, 0U, (uint32_t)(data_bit_length >> 32U));
  PACK_U32_BE(data_bit_length_be_bytes, 4U, (uint32_t)(data_bit_length & 0xFFFFFFFFU));
  sha1_process(ctx, data_bit_length_be_bytes, sizeof data_bit_length_be_bytes);

  PACK_U32_BE(result, 0U, ctx->h[0U]);
  PACK_U32_BE(result, 4U, ctx->h[1U]);
  PACK_U32_BE(result, 8U, ctx->h[2U]);
  PACK_U32_BE(result, 12U, ctx->h[3U]);
  PACK_U32_BE(result, 16U, ctx->h[4U]);
}

char* sha1_to_string(const uint8_t hash[static 20U])
{
  size_t str_index = 0U;

  /* 2 hex characters for every uint8_t and NULL terminator. */
  size_t str_length = 2U * 20U + 1U;

  char *str = malloc(str_length * sizeof *str);
  if (str != NULL)
  {
    for (size_t i = 0U; i < 20U; i++)
    {
      str[str_index++] = nibble_to_hex_char(hash[i] >> 4U);
      str[str_index++] = nibble_to_hex_char(hash[i] & 0xFU);
    }

    str[str_index] = '\0';
  }

  return str;
}
