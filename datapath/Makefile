ARCH_INC := /usr/include/$(shell uname -m)-linux-gnu
BUILD := build

all: $(BUILD)/glasswall.bpf.o $(BUILD)/agent

bpf/config_gen.h $(BUILD)/agent.conf: ../config/glasswall.yaml ../config/features.yaml gen_config.py
	/opt/glasswall/venv/bin/python gen_config.py

$(BUILD)/glasswall.bpf.o: bpf/glasswall.bpf.c bpf/glasswall_common.h bpf/config_gen.h
	mkdir -p $(BUILD)
	clang -O2 -g -target bpf -I$(ARCH_INC) -c $< -o $@

$(BUILD)/agent: agent/agent.c bpf/glasswall_common.h bpf/config_gen.h
	mkdir -p $(BUILD)
	gcc -O2 -Wall -o $@ $< -lbpf -lelf -lz

clean:
	rm -rf $(BUILD) bpf/config_gen.h

.PHONY: all clean
