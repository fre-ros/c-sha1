#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"
#include "test_util.h"

static char hash_string[SHA1_STR_LEN];

static void sha1_test(const struct test_data *test)
{
  uint8_t hash[SHA1_HASH_LEN];
  sha1(test->msg, test->msg_length, hash);
  sha1_to_str_buffer(hash, hash_string);

  assert(strcmp(hash_string, test->expected_hash) == 0);
}

static void sha1_streaming_one_call_test(const struct test_data *test)
{
  uint8_t hash[SHA1_HASH_LEN];

  sha1_ctx ctx;
  sha1_init(&ctx);
  sha1_process(&ctx, test->msg, test->msg_length);
  sha1_finalize(&ctx, hash);

  sha1_to_str_buffer(hash, hash_string);
  assert(strcmp(hash_string, test->expected_hash) == 0);
}

static void sha1_streaming_test(const struct test_data *test)
{
  sha1_ctx ctx;
  size_t data_left;
  size_t chunk_size;
  size_t len_to_process;
  uint8_t hash[SHA1_HASH_LEN];

  size_t chunk_sizes[] = {
    1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U,
    60U, 61U, 62U, 63U, 64U, 65U, 66U, 67U, 68U, 69U
  };

  for (size_t chunk_size_idx = 0U; chunk_size_idx < (sizeof chunk_sizes / sizeof chunk_sizes[0U]); chunk_size_idx++)
  {
    sha1_init(&ctx);
    data_left = test->msg_length;
    chunk_size = chunk_sizes[chunk_size_idx];

    while (data_left > 0U)
    {
      len_to_process = (data_left >= chunk_size) ? chunk_size : data_left;
      sha1_process(&ctx, &test->msg[test->msg_length - data_left], len_to_process);
      data_left -= len_to_process;
    }

    sha1_finalize(&ctx, hash);
    sha1_to_str_buffer(hash, hash_string);
    assert(strcmp(hash_string, test->expected_hash) == 0);
  }
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
