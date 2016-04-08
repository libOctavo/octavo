CARGO_CMD = cargo

TASK ?= test

packages = digest crypto kdf mac

all: $(packages) octavo

octavo:
	$(CARGO_CMD) $(TASK)

$(packages):
	$(CARGO_CMD) $(TASK) --manifest-path "$@/Cargo.toml"

.PHONY: all $(packages)
