CC=gcc
CFLAGS=`pkg-config libusb-1.0 libosmocore libosmoabis --cflags` -O2 -Wall
LDLIBS=`pkg-config libusb-1.0 libosmocore libosmoabis --libs`

OBJS=main dump

all: $(OBJS)

main: idt82v2081.o idt82v2081_usb.o main.o

dump: dump.o

clean:
	rm -f $(OBJS) *.o
