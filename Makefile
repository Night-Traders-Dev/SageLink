SAGE ?= sage
ROOT := $(abspath .)
BUILD_DIR := $(ROOT)/build
TARGET := $(BUILD_DIR)/sagelink.elf
ENTRYPOINT := $(ROOT)/sagelink/cli/sagelink.sage

.PHONY: all build test clean run

all: build

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

build: $(BUILD_DIR)
	$(SAGE) --compile-bare $(ENTRYPOINT) -o $(TARGET) -I $(ROOT)

run: build
	$(TARGET)

test:
	$(SAGE) $(ROOT)/Testing/test_crypto.sage
	$(SAGE) $(ROOT)/Testing/test_handshake.sage
	$(SAGE) $(ROOT)/Testing/test_integration.sage

clean:
	rm -rf $(BUILD_DIR)