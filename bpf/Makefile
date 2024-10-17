#!make

SHELL = bash

.PHONY: format
format:
	find . -regex '.*\.\(c\|h\)' -exec clang-format -style=file -i {} \;
