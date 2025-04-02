TARGET = mail_inet
SRC = $(TARGET).c  
CFLAGS = -I/usr/include/postgresql
LIBS = -lsodium -lpq -pthread

$(TARGET): $(SRC)
	gcc -o $(TARGET) $(SRC) $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)
