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

extern void sha1(const uint8_t *data, size_t size, uint8_t result[static 20U]);
extern void sha1_init(sha1_ctx *ctx);
extern void sha1_process(sha1_ctx *ctx, const uint8_t *data, size_t size);
extern void sha1_finalize(sha1_ctx *ctx, uint8_t result[static 20U]);
extern char* sha1_to_string(const uint8_t hash[static 20U]);

#endif /* SHA1_H_ */
