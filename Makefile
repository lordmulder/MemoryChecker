OUTPUT = bin/memchckr.exe
SOURCE = $(wildcard src/*.c)

RESSRC = res/version.rc
RESOBJ = obj/rc.obj

CFLAGS = -DNDEBUG -Ofast -march=x86-64 -mtune=generic -flto -municode -static -s

.PHONY: all

all: $(OUTPUT)

$(OUTPUT): $(SOURCE) $(RESSRC)
	mkdir -p $(dir $(OUTPUT)) $(dir $(RESOBJ))
	windres $(RESSRC) $(RESOBJ)
	$(CC) $(CFLAGS) -o $(OUTPUT) $(SOURCE) $(RESOBJ)
