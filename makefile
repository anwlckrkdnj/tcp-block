LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o detect.o bm.o forward.o backward.o mac.o ip.o ethhdr.o info.o mymac.o calc.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
