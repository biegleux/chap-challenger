CC=gcc
LDLIBS=-lpcap
TARGET=chap-challenger

all: $(TARGET)

$(TARGET):
	$(CC) -o $@ chap-challenger.c $(LDLIBS)

clean:
	rm -rf *o $(TARGET)
