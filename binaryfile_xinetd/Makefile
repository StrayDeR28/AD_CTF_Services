TARGET = mail_panda
SRC = $(TARGET).c  
LIBS = -lsodium -lrdkafka -O0 -fno-stack-protector -no-pie -Wno-format-security

$(TARGET): $(SRC)
	gcc -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
