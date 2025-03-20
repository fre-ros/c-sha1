#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"
#include "test_util.h"

static char hash_string[41];

static void sha1_test(const struct test_data *test)
{
  uint8_t hash[20];
  sha1(test->msg, test->msg_length, hash);
  sha1_to_string_static(hash, hash_string);

  assert(strcmp(hash_string, test->expected_hash) == 0);
}

static void sha1_streaming_one_call_test(const struct test_data *test)
{
  uint8_t hash[20];

  sha1_ctx ctx;
  sha1_init(&ctx);
  sha1_process(&ctx, test->msg, test->msg_length);
  sha1_finalize(&ctx, hash);

  sha1_to_string_static(hash, hash_string);
  assert(strcmp(hash_string, test->expected_hash) == 0);
}

static void sha1_streaming_test(const struct test_data *test)
{
  uint8_t hash[20];

  sha1_ctx ctx;
  sha1_init(&ctx);

  for (size_t i = 0; i < test->msg_length; i++)
  {
    sha1_process(&ctx, &test->msg[i], 1U);
  }

  sha1_finalize(&ctx, hash);

  sha1_to_string_static(hash, hash_string);
  assert(strcmp(hash_string, test->expected_hash) == 0);
}

static void run_sha1_tests(struct test_data *tests, size_t number_of_tests, const char *test_name)
{
  printf("%s...", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    sha1_test(&tests[i]);
    sha1_streaming_one_call_test(&tests[i]);
    sha1_streaming_test(&tests[i]);
  }
  puts("OK");
}

int main(void)
{
  size_t number_of_tests;
  struct test_data *test_data;

  test_data = load_test_file("test/nist_test_vectors/SHA1ShortMsg.rsp", &number_of_tests);
  run_sha1_tests(test_data, number_of_tests, "SHA1 short");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA1LongMsg.rsp", &number_of_tests);
  run_sha1_tests(test_data, number_of_tests, "SHA1 long.");
  free_test_data(test_data, number_of_tests);

  return 0;
}
