def ImgEncrypt(img, message):
    lenBits = (len(message) * 8) + 1
    width = img.size[0]
    height = img.size[1] 
    _h = int(height / 2)
    _w = int(width / 2)

    pix = img.load() 

    binMsg = bin(int.from_bytes(message.encode(), "big"))

    count = 2
    a0 = pix[_w, _h][0]  # red
    b0 = pix[_w, _h][1]  # green
    c0 = pix[_w, _h][2]  # blue
    if binMsg[0] == "1":
        if (b0 % 2) == 0:
            pix[_w, _h] = (a0, b0 + 1, c0)

    else:
        if (b0 % 2) == 1:
            if b0 == 255:
                pix[_w, _h] = (a0, 254, c0)
            else:
                pix[_w, _h] = (a0, b0 + 1, c0)

    _w = _w + 1
    while _h < height:
        for i in range(_w, width):
            a = pix[i, _h][0]  # red
            b = pix[i, _h][1]  # green
            c = pix[i, _h][2]  # blue

            if count < lenBits:
                if binMsg[count] == "1":
                    count = count + 1
                    if (b % 2) == 0:
                        pix[i, _h] = (a, b + 1, c)

                else:
                    count = count + 1
                    if (b % 2) == 1:
                        if b == 255:
                            pix[i, _h] = (a, 254, c)
                        else:
                            pix[i, _h] = (a, b + 1, c)

            else:
                i = width
                break

        if count < lenBits:
            _h = _h + 1
            _w = 0
        else:
            _h = height
            break

    return img
