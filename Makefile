OUTPUT = bin/MemoryChecker.exe
CFLAGS = -pipe -Wall -Ofast -DNDEBUG -march=x86-64 -mtune=generic -flto -municode -static -s
SOURCE = $(wildcard src/*.c)
WNDRES = $(addprefix obj/,$(patsubst %.rc,%.res.o,$(notdir $(wildcard res/*.rc))))

.PHONY: all clean

all: $(OUTPUT)

$(OUTPUT): $(SOURCE) $(WNDRES)
	@mkdir -v -p $(dir $@)
	$(CC) $(CFLAGS) -o $(OUTPUT) $(SOURCE) $(WNDRES)

obj/%.res.o: res/%.rc
	@mkdir -v -p $(dir $@)
	windres -o $@ $<

clean:
	rm -v -f obj/*.o bin/*.exe
