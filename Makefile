TARGET = MAIL
SRC = $(TARGET).c  
CFLAGS = -I/usr/include/postgresql
LIBS = -lsodium -lpq

$(TARGET): $(SRC)
	gcc -o $(TARGET) $(SRC) $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)
