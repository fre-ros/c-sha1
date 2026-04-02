# c-sha1

[SHA1](https://en.wikipedia.org/wiki/SHA-1) library for C

- Supports one call calculation and streaming protocol
- Requires C standard C99 or newer
- Implementation verified against [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) test vectors
- Allocation free implementation (Except for optional **sha1_to_str** function)

## Usage
To use the library add `sha1.h` and `sha1.c` to your project.
<br>**Example:**
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sha1.h"

static void print_hash(const uint8_t hash[SHA1_HASH_LEN])
{
  char *hash_str = sha1_to_str(hash);
  if (hash_str != NULL)
  {
    puts(hash_str);
    free(hash_str);
  }
}

static void print_hash_without_allocation(const uint8_t hash[SHA1_HASH_LEN])
{
  char hash_str[SHA1_STR_LEN];
  sha1_to_str_buffer(hash, hash_str);
  puts(hash_str);
}

int main(void)
{
  uint8_t hash[SHA1_HASH_LEN];

  // Calculate hash in one call
  const char *msg = "The quick brown fox jumps over the lazy dog.";
  sha1((const uint8_t*)msg, strlen(msg), hash);
  print_hash(hash);

  // Calculate hash with streaming protocol
  const char *msg_part_one = "The quick brown fox ";
  const char *msg_part_two = "jumps over the lazy dog.";

  sha1_ctx ctx;
  sha1_init(&ctx);
  sha1_process(&ctx, (const uint8_t*)msg_part_one, strlen(msg_part_one));
  sha1_process(&ctx, (const uint8_t*)msg_part_two, strlen(msg_part_two));
  sha1_finalize(&ctx, hash);
  print_hash_without_allocation(hash);

  return 0;
}

// Output:
//  408d94384216f890ff7a0c3528e8bed1e0b01621
//  408d94384216f890ff7a0c3528e8bed1e0b01621
```

## API
The string returned from **sha1_to_str** must be freed by the caller.
<br>Use **sha1_to_str_buffer** to create a string without allocation.

```c
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
```

## Test
The test checks all [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) test vectors against the implementation.
The tests can be run by calling make.

```shell
$ make
SHA1 short...OK
SHA1 long....OK
```
