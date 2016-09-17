CARGO_CMD = cargo

TASK ?= test

packages = digest crypto kdf mac

all: $(packages) octavo

octavo:
	$(CARGO_CMD) $(TASK)

$(packages):
	$(CARGO_CMD) $(TASK) --manifest-path "$@/Cargo.toml"

doc:
	cargo doc
	bash tools/doc-upload.sh

.PHONY: all $(packages)
