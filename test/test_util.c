#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "test_util.h"

/* Guaranteed to hold the longest lines in the test files. */
#define BUFFER_SIZE            52000
#define BUFFER_SIZE_SCANF_STR "51999"

static char msg_buffer[BUFFER_SIZE];
static char line_buffer[BUFFER_SIZE];

static uint8_t hex_nibble_to_u8(char nibble)
{
  switch(tolower(nibble))
  {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    {
      return (uint8_t)(nibble - '0');
    }

    case 'a': return 10;
    case 'b': return 11;
    case 'c': return 12;
    case 'd': return 13;
    case 'e': return 14;
    case 'f': return 15;

    default:
    {
      assert(0);
    }
  }

  // Will never get here but compiler will warn
  return 0;
}

static void convert_msg_hex_string_to_msg_data(struct test_data *test_data, const char *str)
{
  size_t str_length = strlen(str);
  size_t msg_data_length = str_length / 2; // Every character is a HEX nibble

  assert(str_length % 2 == 0);

  uint8_t *msg_data = malloc(msg_data_length * sizeof *msg_data);
  assert(msg_data != NULL);

  for (size_t i = 0; i < str_length; i += 2)
  {
    msg_data[i/2] = (hex_nibble_to_u8(str[i]) << 4) | hex_nibble_to_u8(str[i+1]);
  }

  test_data->msg = msg_data;
  test_data->msg_length = msg_data_length;
}

static void load_test_case(struct test_data *test_data, FILE *f)
{
  size_t msg_length;

  // Read length field line
  assert(fgets(line_buffer, sizeof line_buffer, f) != NULL);
  assert(sscanf(line_buffer, "Len = %zu", &msg_length) == 1);

  // Read message line
  assert(fgets(line_buffer, sizeof line_buffer, f) != NULL);
  line_buffer[strcspn(line_buffer, "\r\n")] = 0      ;
  assert(sscanf(line_buffer, "Msg = %"BUFFER_SIZE_SCANF_STR"s", msg_buffer) == 1);

  if (msg_length > 0)
  {
    convert_msg_hex_string_to_msg_data(test_data, msg_buffer);
  }
  else
  {
    test_data->msg_length = 0;
  }

  // Read hash line
  assert(fgets(line_buffer, sizeof line_buffer, f) != NULL);
  line_buffer[strcspn(line_buffer, "\r\n")] = 0;
  assert(sscanf(line_buffer, "MD = %40s", test_data->expected_hash) == 1);

  // Consume empty line
  assert(fgets(line_buffer, sizeof line_buffer, f) != NULL);
}

struct test_data* load_test_file(const char *filepath, size_t *number_of_tests)
{
  FILE *f = fopen(filepath, "r");
  assert(f != NULL);

  *number_of_tests = 0;

  while (fgets(line_buffer, sizeof line_buffer, f) != NULL)
  {
    if (sscanf(line_buffer, "[L = %zu]", number_of_tests) == 1)
    {
      break;
    }
  }

  assert(*number_of_tests != 0);

  // Consume empty line
  assert(fgets(line_buffer, sizeof line_buffer, f) != NULL);

  struct test_data *test_data = malloc(*number_of_tests * sizeof *test_data);
  assert(test_data != NULL);

  for (size_t i = 0; i < *number_of_tests; i++)
  {
    load_test_case(&test_data[i], f);
  }

  fclose(f);

  return test_data;
}

void free_test_data(struct test_data *test_data, size_t number_of_tests)
{
  for (size_t i = 0; i < number_of_tests; i++)
  {
    if (test_data[i].msg_length > 0)
    {
      free(test_data[i].msg);
    }
  }
  free(test_data);
}
