CARGO_CMD = cargo

TASK ?= test

packages = digest crypto kdf mac

all: $(packages) octavo

octavo:
	$(CARGO_CMD) $(TASK) --verbose

$(packages):
	$(CARGO_CMD) $(TASK) $(CARGO_OPTS) --manifest-path "$@/Cargo.toml"

doc:
	env RUSTDOCFLAGS="--html-in-header docs/header.html --html-after-content docs/after.html" $(CARGO_CMD) doc $(CARGO_OPTS)

doc-upload: doc
	bash tools/doc-upload.sh

.PHONY: all $(packages) doc doc-upload
