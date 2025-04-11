TARGET = mail_panda
SRC = $(TARGET).c  
LIBS = -lsodium -lrdkafka -pthread

$(TARGET): $(SRC)
	gcc -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
