CARGO_CMD = cargo

TASK ?= test

packages = digest crypto kdf mac

all: $(packages)
	$(CARGO_CMD) test

$(packages):
	$(CARGO_CMD) $(TASK) --manifest-path "$@/Cargo.toml"

.PHONY: all $(packages)
