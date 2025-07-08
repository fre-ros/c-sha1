#ifndef SHA1_H_
#define SHA1_H_

#include <stdint.h>
#include <stddef.h>

#define SHA1_HASH_LEN 20U
#define SHA1_STR_LEN ((SHA1_HASH_LEN * 2U) + 1U)

typedef struct {
  size_t chunk_idx;
  uint64_t msg_len;
  uint32_t h[5U];
  uint8_t chunk[64U];
} sha1_ctx;

extern void sha1(const uint8_t *data, size_t size, uint8_t result[static SHA1_HASH_LEN]);
extern void sha1_init(sha1_ctx *ctx);
extern void sha1_process(sha1_ctx *ctx, const uint8_t *data, size_t size);
extern void sha1_finalize(sha1_ctx *ctx, uint8_t result[static SHA1_HASH_LEN]);
extern char* sha1_to_str(const uint8_t hash[static SHA1_HASH_LEN]);
extern void sha1_to_str_buffer(const uint8_t hash[static SHA1_HASH_LEN], char dst[static SHA1_STR_LEN]);

#endif /* SHA1_H_ */
