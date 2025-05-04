TARGET = mail_panda
SRC = $(TARGET).c
LIBS = -lsodium -lhiredis -O0 -fno-stack-protector -no-pie -Wno-format-security
OBJECTS = cJSON.o

all: $(TARGET)

$(TARGET): $(SRC) $(OBJECTS) cJSON.h
	gcc -o $(TARGET) $(SRC) $(OBJECTS) $(LIBS) -I.

cJSON.o: cJSON.c cJSON.h
	gcc -c cJSON.c -o cJSON.o -I.

clean:
	rm -f $(TARGET) $(OBJECTS)
