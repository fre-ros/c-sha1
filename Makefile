 ifeq ($(OS), Windows_NT)
	EXTRA_TEST_FLAGS :=
else
	EXTRA_TEST_FLAGS := -fsanitize=address,undefined,leak -fstack-protector-all
endif

all:
	@gcc -std=c99 -Wall -Wextra -Werror -Wpedantic -Wconversion $(EXTRA_TEST_FLAGS) -Isrc src/sha1.c test/test_util.c test/test.c -o test/run_tests
	@test/run_tests
