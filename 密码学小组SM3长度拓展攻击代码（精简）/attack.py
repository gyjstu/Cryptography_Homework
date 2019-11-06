import binascii
from math import ceil
from gmssl.func import rotl, bytes_to_list
from gmssl import sm3, func

#下面是算法固定的值和算法过程
T_j = [
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
]

def sm3_ff_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        ret = (x & y) | (x & z) | (y & z)
    return ret

def sm3_gg_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        ret = (x & y) | ((~ x) & z)
    return ret

def sm3_p_0(x):
    return x ^ (rotl(x, 9 % 32)) ^ (rotl(x, 17 % 32))

def sm3_p_1(x):
    return x ^ (rotl(x, 15 % 32)) ^ (rotl(x, 23 % 32))
#cf是单次压缩函数，v是上次的结果，b是这次加的明文块
def sm3_cf(v_i, b_i):
    w = []
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i*4,(i+1)*4):
            data = data + b_i[k]*weight
            weight = int(weight/0x100)
        w.append(data)

    for j in range(16, 68):
        w.append(0)
        w[j] = sm3_p_1(w[j-16] ^ w[j-9] ^ (rotl(w[j-3], 15 % 32))) ^ (rotl(w[j-13], 7 % 32)) ^ w[j-6]
        str1 = "%08x" % w[j]
    w_1 = []
    for j in range(0, 64):
        w_1.append(0)
        w_1[j] = w[j] ^ w[j+4]
        str1 = "%08x" % w_1[j]

    a, b, c, d, e, f, g, h = v_i

    for j in range(0, 64):
        ss_1 = rotl(
            ((rotl(a, 12 % 32)) +
            e +
            (rotl(T_j[j], j % 32))) & 0xffffffff, 7 % 32
        )
        ss_2 = ss_1 ^ (rotl(a, 12 % 32))
        tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff
        tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff
        d = c
        c = rotl(b, 9 % 32)
        b = a
        a = tt_1
        h = g
        g = rotl(f, 19 % 32)
        f = e
        e = sm3_p_0(tt_2)

        a, b, c, d, e, f, g, h = map(
            lambda x:x & 0xFFFFFFFF ,[a, b, c, d, e, f, g, h])

    v_j = [a, b, c, d, e, f, g, h]
    return [v_j[i] ^ v_i[i] for i in range(8)]

#下面是为了创造b
#meg是要添加的信息，目前只加了一个"a"
def sm3at(msg,len0):
    # print(msg)
    len1 = len0+len(msg)#len0是真明文填充后的长度，为了简化攻击过程，这里并没有通过遍历去猜测而是直接输入了这个值
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64
    for i in range(reserve1, range_end):
        msg.append(0x00)
#下面应该是给长度64bit的位置然后显示成10进制并放到消息队尾，每字节是0-255，超过就进一
    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7-i])
    #现在msg是填充完的明文信息
    return msg

def sixteen_to_ten(str1:str)->list:
    list1_ = []
    i = 0
    while  i < len(str1):
        a = str1[i:i+8]
        list1_.append(int(a,16))
        i = i+8
    return list1_

if __name__ == '__main__':
    #下面是真正信息的hash值 此处是"bcde"的hash值
    hashcode="29890a124a4a56218fbe528fb20ea71a43b8c2f4cdbe08fbec6bc8a9a27a8430"
    #把填充的信息的内容和真正信息的长度(字节)输入给拓展信息函数 此处拓展的内容是一个"a"
    y = sm3at(func.bytes_to_list(b"a"),64*1)

    #v是根据真正信息的hash值还原成的的压缩结果
    v = []
    v=sixteen_to_ten(hashcode)

    #下面人工进行最后一轮压缩
    #为了简化攻击过程，本次只进行一轮压缩，即添加的信息不能超过55字节
    p=sm3_cf(v, y)
    #把压缩结果转化为hash码
    result = ""
    for i in p:
        result = '%s%08x' % (result, i)
    print(result)
    #此时这个hash值的原文相当于"bcdex80x00...x00a"
    #下面是输入的消息真正的样子，用ascii码表示，x80是算法默认填充的 显示为128，中间的0为了使整个数据为512bit的整数倍，32是"bcde"占用的bit数，最后的97是我们添加的信息"a"
    #[98, 99, 100, 101, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,97]
