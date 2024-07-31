CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap -lnet

SRCS = pcap-test.c
OBJS = $(SRCS:.c=.o)

TARGET = pcap-test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c pcap-test.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
