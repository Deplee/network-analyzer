CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
LDFLAGS = -lpcap -lpthread

TARGET = net_analyzer
SOURCES = src/main.c src/packet_analyzer.c src/statistics.c src/utils.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET) 