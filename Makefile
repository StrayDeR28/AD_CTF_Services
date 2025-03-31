TARGET = mail
SRC = $(TARGET).c  

$(TARGET): $(SRC)
	gcc -o $(TARGET) $(SRC) -lsodium  

clean:
	rm -f $(TARGET)
