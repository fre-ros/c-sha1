#ifndef TEST_UTIL_H_
#define TEST_UTIL_H_

#include <stdint.h>

struct test_data
{
  uint8_t *msg;
  size_t msg_length;
  char expected_hash[41];
};

extern struct test_data* load_test_file(const char *filepath, size_t *number_of_tests);
extern void free_test_data(struct test_data *test_data, size_t number_of_tests);

#endif /* TEST_UTIL_H_ */
