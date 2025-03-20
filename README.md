# c-sha1

[SHA1](https://en.wikipedia.org/wiki/SHA-1) library for C

- Supports one call calculation and streaming protocol
- Requires C99 or newer
- Implementation verified against [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) test vectors

## Usage
To use the library add `sha1.h` and `sha1.c` to your project.

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sha1.h"

static void print_hash(const uint8_t hash[20])
{
  char *hash_str = sha1_to_string(hash);
  if (hash_str != NULL)
  {
    puts(hash_str);
    free(hash_str);
  }
}

static void print_hash_without_allocation(const uint8_t hash[20])
{
  char hash_str[41];
  sha1_to_string_static(hash, hash_str);
  puts(hash_str);
}

int main(void)
{
  const char *msg = "The quick brown fox jumps over the lazy dog.";

  uint8_t hash[20];

  // Calculate hash in one call
  sha1((uint8_t*)msg, strlen(msg), hash);
  print_hash(hash);

  // Calculate hash with streaming protocol
  const char *msg_part_one = "The quick brown fox ";
  const char *msg_part_two = "jumps over the lazy dog.";

  sha1_ctx ctx;
  sha1_init(&ctx);
  sha1_process(&ctx, (uint8_t*)msg_part_one, strlen(msg_part_one));
  sha1_process(&ctx, (uint8_t*)msg_part_two, strlen(msg_part_two));
  sha1_finalize(&ctx, hash);
  print_hash_without_allocation(hash);

  return 0;
}

// Output:
//  408d94384216f890ff7a0c3528e8bed1e0b01621
//  408d94384216f890ff7a0c3528e8bed1e0b01621
```

## API
The string returned from **sha1_to_string** must be freed by the caller.
Use **sha1_to_string_static** to create a string without allocation.
```c
extern void sha1(const uint8_t *data, size_t size, uint8_t result[static 20U]);
extern void sha1_init(sha1_ctx *ctx);
extern void sha1_process(sha1_ctx *ctx, const uint8_t *data, size_t size);
extern void sha1_finalize(sha1_ctx *ctx, uint8_t result[static 20U]);
extern char* sha1_to_string(const uint8_t hash[static 20U]);
extern void sha1_to_string_static(const uint8_t hash[static 20U], char dst[static 41U]);
```

## Test
The tests are run by calling make.

```shell
$ make
SHA1 short...OK
SHA1 long....OK
```
