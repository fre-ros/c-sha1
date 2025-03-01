 ifeq ($(OS), Windows_NT)
	EXTRA_TEST_FLAGS :=
else
	EXTRA_TEST_FLAGS := -fsanitize=address,undefined,leak -fstack-protector-all
endif

CPPCHECK := 1

all:
ifeq ($(CPPCHECK), 1)
	@cppcheck --std=c99 -Isrc -Itest --enable=warning,portability,unusedFunction --max-ctu-depth=4 --check-level=exhaustive src/ test/
endif
	@gcc -std=c99 -Wall -Wextra -Werror -Wpedantic $(EXTRA_TEST_FLAGS) -Isrc src/sha1.c test/test_util.c test/test.c -o test/run_tests
	@test/run_tests
