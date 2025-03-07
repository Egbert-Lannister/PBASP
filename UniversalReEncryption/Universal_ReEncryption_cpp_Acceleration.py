import universal_reencryption


if __name__ == '__main__':

    # 初始化（安全参数示例为8位，实际应用需大得多）
    ure = universal_reencryption.UniversalReEncryption(8)
    print("公钥:", ure.public_key)
    print("私钥:", ure.private_key)
    print("部分密钥: partial_key1 =", ure.partial_key1, ", partial_key2 =", ure.partial_key2)

    bitmap = "1010100110"
    print("原始位图字符串:", bitmap)

    # 加密
    encrypted = ure.encrypt_bitmap(bitmap)
    print("加密后的密文列表:", encrypted)

    # 重加密
    reencrypted = ure.reencrypt_bitmap(encrypted)
    print("重加密后的密文列表:", reencrypted)

    # 分布式解密（这里以直接解密演示）
    decrypted = ure.decrypt_bitmap(encrypted)
    print("解密后的位图字符串:", decrypted)


