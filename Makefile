CARGO_CMD = cargo

TASK ?= test

packages = digest crypto kdf mac

all: $(packages) octavo

octavo:
	$(CARGO_CMD) $(TASK) --verbose

$(packages):
	$(CARGO_CMD) $(TASK) --verbose --manifest-path "$@/Cargo.toml"

doc:
	$(CARGO_CMD) doc --verbose

doc-upload: doc
	bash tools/doc-upload.sh

.PHONY: all $(packages) doc doc-upload
