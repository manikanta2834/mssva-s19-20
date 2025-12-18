CC=gcc
CFLAGS=-Wall -O2 -Iinclude
BIN=bin

all: dirs imd telemetry

dirs:
	mkdir -p $(BIN)

imd:
	$(CC) $(CFLAGS) daemon/main.c daemon/imd_helpers.c -o $(BIN)/imd

telemetry:
	$(CC) $(CFLAGS) telemetry/main.c -o $(BIN)/imd_telemetry

clean:
	rm -rf bin/*
	rm -f /tmp/important.conf /tmp/secure_data
