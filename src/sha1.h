#ifndef SHA1_H_
#define SHA1_H_

#include <stdint.h>
#include <stddef.h>

/** SHA1 digest length in bytes. */
#define SHA1_HASH_LEN 20U

/** Buffer size needed for a SHA1 hash string representation. */
#define SHA1_STR_LEN ((SHA1_HASH_LEN * 2U) + 1U)

/**
 * SHA1 hashing context.
 *
 * Stores intermediate state during incremental processing.
 */
typedef struct {
  /** Current position in chunk buffer. */
  size_t chunk_idx;

  /** Total processed message length in bytes. */
  uint64_t msg_len;

  /** Internal hash state. */
  uint32_t h[5U];

  /** Chunk buffer, when this gets filled it will processed and the internal hash state will be updated. */
  uint8_t chunk[64U];
} sha1_ctx;

/**
 * Compute SHA1 digest for a complete buffer.
 *
 * @param[in]   data    Input data buffer.
 * @param[in]   size    Input size in bytes.
 * @param[out]  result  Output digest buffer, has to be at least SHA1_HASH_LEN in size.
 */
extern void sha1(const uint8_t *data, size_t size, uint8_t result[static SHA1_HASH_LEN]);

/**
 * Initialize a SHA1 context.
 *
 * This should be called when beginning a new hash calculation using the streaming protocol.
 * Then make one or multiple calls to sha1_process to process data and finally one call to sha1_finalize
 * to compute the final digest.
 *
 * @param[in,out]  ctx  SHA1 context.
 */
extern void sha1_init(sha1_ctx *ctx);

/**
 * Process data for a SHA1 context.
 *
 * @param[in,out]  ctx   SHA1 context.
 * @param[in]      data  Data to process.
 * @param[in]      size  Data length.
 */
extern void sha1_process(sha1_ctx *ctx, const uint8_t *data, size_t size);

/**
 * Finalize the SHA1 computation producing the final digest.
 *
 * This call is destructive, any consecutive calls to the same function will not return the same digest.
 * Also adding more data after a call to this function would not yield the expected result.
 * Call sha1_init to start a new calculation.
 *
 * @param[in,out]  ctx     SHA1 context.
 * @param[out]     result  Buffer to place the result in, has to be at least SHA1_HASH_LEN in size.
 */
extern void sha1_finalize(sha1_ctx *ctx, uint8_t result[static SHA1_HASH_LEN]);

/**
 * Allocates and creates a string with the hexadecimal representation of the passed SHA1 hash.
 *
 * This function will call malloc to allocate memory for the string, it's up to the caller to free that memory.
 * If allocation fails, NULL will be returned. To create a string without allocation use sha1_to_str_buffer
 * instead.
 * The resulting string will be in lowercase.
 *
 * @param[in]  hash  The SHA1 hash to create a string for, has to be at least SHA224_HASH_LEN in size.
 *
 * @return     Resulting string on success, otherwise NULL. Must be freed by the caller.
 */
extern char* sha1_to_str(const uint8_t hash[static SHA1_HASH_LEN]);

/**
 * Creates a string with the hexadecimal representation of the passed SHA1 hash.
 *
 * The resulting string will be placed in the passed char buffer, no allocations will be made.
 * The resulting string will be in lowercase.
 *
 * @param[in]   hash  The SHA1 hash to create a string for, has to be at least SHA1_HASH_LEN in size.
 * @param[out]  dst   The destination buffer to place the string, has to be at least SHA1_STR_LEN in size.
 */
extern void sha1_to_str_buffer(const uint8_t hash[static SHA1_HASH_LEN], char dst[static SHA1_STR_LEN]);

#endif /* SHA1_H_ */
