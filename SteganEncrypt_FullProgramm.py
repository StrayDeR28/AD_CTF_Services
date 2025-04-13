import numpy
from PIL import Image, ImageDraw

def ImgEncrypt(PathImg, message):
    lenBits = (len(message) * 8) + 1   # ���������� �����

    orig_img = Image.open(PathImg)     # ��������� �����������
    img = orig_img.copy()              # �������� �����������, ����� �� ��������� ��������
    orig_img.close()                   # ��������� �������� � �������� � ������

    width = img.size[0]                # ���������� ������ �����������
    height = img.size[1]               # ���������� ������ �����������
    _h = int(height / 2);              # ������� ������� �� ������
    _w = int(width / 2);               # ������� ������� �� ������

    pix = img.load()                   # ��������� �������� ��������
    
    binMsg = bin(int.from_bytes(message.encode(), "big"))
    #print("binMsg:", binMsg)
    #quit()

    count = 2;
    a0 = pix[_w, _h][0]   #red
    b0 = pix[_w, _h][1]   #green
    c0 = pix[_w, _h][2]   #blue
    # ���� � ���� ����� 1
    if (binMsg[0] == "1"):
        # ���� green - ������ (� ����� ������� ��������)
        if ((b0 % 2) == 0):
            # [0;254] --> [1;255]
            pix[_w, _h] = (a0, b0 + 1, c0)

    # ���� � ���� ����� 0
    else:
        # ���� green - �������� (� ����� ������� ������)
        if ((b0 % 2) == 1):
            # ���� green == 255
            if (b0 == 255):
                pix[_w, _h] = (a0, 254, c0)
            # ���� green != 255 ([1;253] --> [2;254])
            else:
                pix[_w, _h] = (a0, b0 + 1, c0)



    _w = _w + 1
    while (_h < height):
        for i in range(_w, width):
            a = pix[i, _h][0]   #red
            b = pix[i, _h][1]   #green
            c = pix[i, _h][2]   #blue

            if (count < lenBits):
                # ���� � ���� ����� 1
                if (binMsg[count] == "1"):
                    count = count + 1

                    # ���� green - ������ (� ����� ������� ��������)
                    if ((b % 2) == 0):
                        # [0;254] --> [1;255]
                        pix[i, _h] = (a, b + 1, c)

                # ���� � ���� ����� 0
                else:
                    count = count + 1

                    # ���� green - �������� (� ����� ������� ������)
                    if ((b % 2) == 1):
                        # ���� green == 255
                        if (b == 255):
                            pix[i, _h] = (a, 254, c)
                        # ���� green != 255 ([1;253] --> [2;254])
                        else:
                            pix[i, _h] = (a, b + 1, c)

            # ���� �������� ��� �������
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
    msg = open(PathMsg, "w")         # ��������� ���� ��� ������
    img = Image.open(PathImg)        # ��������� �����������
    width = img.size[0]              # ���������� ������ �����������
    height = img.size[1]             # ���������� ������ �����������
    _h = int(height / 2);            # ������� ������� �� ������
    _w = int(width / 2);             # ������� ������� �� ������
    pix = img.load()                 # ��������� �������� ��������

    count = 0
    lenBits = _len * 8
    decryptBinMsg = ""
    

    # ����������� ���������
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

            # ���� �������� ��� ���� �� ������ ��������
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

    img.close()                      # ��������� �����������
    msg.close()                      # ��������� ���� c ����������






#signature = input("Write your signature: ")
signature = "TEAM005_ABCDEFGHIGKLMNOPQRSTUVWXYZ1234567890qwertyuiop[]"         # ������� ��� ����������
#print("signature:", signature)
ImgEncrypt("C:/Channel/img.png", signature)
ImgDecrypt("C:/Channel/encryptImg.png", "C:/Channel/decryptMsg.txt", len(signature))