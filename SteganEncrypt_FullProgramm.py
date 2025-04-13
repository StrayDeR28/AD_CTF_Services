import numpy
from PIL import Image, ImageDraw

def ImgEncrypt(PathImg, message):
    lenBits = (len(message) * 8) + 1   # определяем длину

    orig_img = Image.open(PathImg)     # открываем изображение
    img = orig_img.copy()              # копируем изображение, чтобы не испортить оригинал
    orig_img.close()                   # закрываем оригинал и работаем с копией

    width = img.size[0]                # определяем ширину изображения
    height = img.size[1]               # определяем высоту изображения
    _h = int(height / 2);              # позиция подписи по высоте
    _w = int(width / 2);               # позиция подписи по ширине

    pix = img.load()                   # выгружаем значения пикселей
    
    binMsg = bin(int.from_bytes(message.encode(), "big"))
    #print("binMsg:", binMsg)
    #quit()

    count = 2;
    a0 = pix[_w, _h][0]   #red
    b0 = pix[_w, _h][1]   #green
    c0 = pix[_w, _h][2]   #blue
    # если в бите стоит 1
    if (binMsg[0] == "1"):
        # если green - чётное (а нужно сделать нечётное)
        if ((b0 % 2) == 0):
            # [0;254] --> [1;255]
            pix[_w, _h] = (a0, b0 + 1, c0)

    # если в бите стоит 0
    else:
        # если green - нечётное (а нужно сделать чётное)
        if ((b0 % 2) == 1):
            # если green == 255
            if (b0 == 255):
                pix[_w, _h] = (a0, 254, c0)
            # если green != 255 ([1;253] --> [2;254])
            else:
                pix[_w, _h] = (a0, b0 + 1, c0)



    _w = _w + 1
    while (_h < height):
        for i in range(_w, width):
            a = pix[i, _h][0]   #red
            b = pix[i, _h][1]   #green
            c = pix[i, _h][2]   #blue

            if (count < lenBits):
                # если в бите стоит 1
                if (binMsg[count] == "1"):
                    count = count + 1

                    # если green - чётное (а нужно сделать нечётное)
                    if ((b % 2) == 0):
                        # [0;254] --> [1;255]
                        pix[i, _h] = (a, b + 1, c)

                # если в бите стоит 0
                else:
                    count = count + 1

                    # если green - нечётное (а нужно сделать чётное)
                    if ((b % 2) == 1):
                        # если green == 255
                        if (b == 255):
                            pix[i, _h] = (a, 254, c)
                        # если green != 255 ([1;253] --> [2;254])
                        else:
                            pix[i, _h] = (a, b + 1, c)

            # если записали все символы
            else:
                i = width
                break

        if (count < lenBits):
            _h = _h + 1
            _w = 0
        else:
            _h = height
            break;

    img.save("C:/Channel/encryptImg.png")
    #img.show()
    img.close()


def ImgDecrypt(PathImg, PathMsg, _len):
    msg = open(PathMsg, "w")         # открываем файл для записи
    img = Image.open(PathImg)        # открываем изображение
    width = img.size[0]              # определяем ширину изображения
    height = img.size[1]             # определяем высоту изображения
    _h = int(height / 2);            # позиция подписи по высоте
    _w = int(width / 2);             # позиция подписи по ширине
    pix = img.load()                 # выгружаем значения пикселей

    count = 0
    lenBits = _len * 8
    decryptBinMsg = ""
    

    # расшифровка сообщения
    while (_h < height):
        for i in range(_w, width):
            b = pix[i, _h][1]

            if (count < lenBits):
                if ((b % 2) == 1):
                    decryptBinMsg = decryptBinMsg + "1"
                    if (count == 0):
                        decryptBinMsg = decryptBinMsg + "b"
                    count = count + 1
                else:
                    decryptBinMsg = decryptBinMsg + "0"
                    if (count == 0):
                        decryptBinMsg = decryptBinMsg + "b"
                    count = count + 1

            # если записали все биты из строки пикселей
            else:
                i = width
                break

        if (count < lenBits):
            _h = _h + 1
            _w = 0
        else:
            _h = height
            break

    #print("")
    #print("decryptBinMsg:", decryptBinMsg)
    #print("")

    m = int(decryptBinMsg, 2)
    decryptMsg = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
    #print("decryptMsg:", decryptMsg)
    #print("")
    msg.write(decryptMsg)

    img.close()                      # закрываем изображение
    msg.close()                      # закрываем файл c сигнатурой






#signature = input("Write your signature: ")
signature = "TEAM005_ABCDEFGHIGKLMNOPQRSTUVWXYZ1234567890qwertyuiop[]"         # подпись для шифрования
#print("signature:", signature)
ImgEncrypt("C:/Channel/img.png", signature)
ImgDecrypt("C:/Channel/encryptImg.png", "C:/Channel/decryptMsg.txt", len(signature))