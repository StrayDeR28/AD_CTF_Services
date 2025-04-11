TARGET = mail_redis
SRC = $(TARGET).c  
LIBS = -lhiredis -lsodium -lpthread

$(TARGET): $(SRC)
	gcc -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
