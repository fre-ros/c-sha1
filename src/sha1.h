#ifndef SHA1_H_
#define SHA1_H_

#include <stdint.h>
#include <stddef.h>

typedef struct {
  size_t msg_len;
  size_t chunk_idx;
  uint32_t h[5U];
  uint8_t chunk[64U];
} sha1_ctx;

extern void sha1(const uint8_t *data, size_t size, uint32_t result[static 5U]);
extern void sha1_init(sha1_ctx *ctx);
extern void sha1_feed(sha1_ctx *ctx, const uint8_t *data, size_t size);
extern void sha1_finalize(sha1_ctx *ctx, uint32_t result[static 5U]);
extern char* sha1_to_string(const uint32_t hash[static 5U]);

#endif /* SHA1_H_ */
