# c-sha1

[SHA1](https://en.wikipedia.org/wiki/SHA-1) library for C

- Supports direct calculation and streaming protocol
- Requires C99 or newer
- Implementation verified against [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) test vectors

## Usage
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sha1.h"

static void print_hash(const uint32_t hash[5])
{
  char *hash_str = sha1_to_string(hash);
  if (hash_str != NULL)
  {
    puts(hash_str);
    free(hash_str);
  }
}

int main(void)
{
  const char *msg = "The quick brown fox jumps over the lazy dog.";

  uint32_t hash[5];

  // Calculate hash in one call
  sha1((uint8_t*)msg, strlen(msg), hash);
  print_hash(hash);

  // Calculate hash with streaming protocol
  const char *msg_part_one = "The quick brown fox ";
  const char *msg_part_two = "jumps over the lazy dog.";

  sha1_ctx ctx;
  sha1_init(&ctx);
  sha1_feed(&ctx, (uint8_t*)msg_part_one, strlen(msg_part_one));
  sha1_feed(&ctx, (uint8_t*)msg_part_two, strlen(msg_part_two));
  sha1_finalize(&ctx, hash);
  print_hash(hash);

  return 0;
}

// Output:
//  408d94384216f890ff7a0c3528e8bed1e0b01621
//  408d94384216f890ff7a0c3528e8bed1e0b01621
```

## API
The string returned from **sha1_to_string** must be freed by the caller.
```c
extern void sha1(const uint8_t *data, size_t size, uint32_t result[static 5U]);
extern void sha1_init(sha1_ctx *ctx);
extern void sha1_feed(sha1_ctx *ctx, const uint8_t *data, size_t size);
extern void sha1_finalize(sha1_ctx *ctx, uint32_t result[static 5U]);
extern char* sha1_to_string(const uint32_t hash[static 5U]);
```

## Test
The tests are run by calling make.
<br>The implementation and test files are analyzed with [cppcheck](https://github.com/danmar/cppcheck) before compiling.
<br>To skip [cppcheck](https://github.com/danmar/cppcheck) pass CPPCHECK=0 to make

```shell
$ make
SHA1 short...OK
SHA1 long....OK
```
