# main.py
from curve import generate_keys, point_to_bytes
import recrypt
import utils


def main():
    # Alice 生成密钥对
    a_pri, a_pub = generate_keys()
    # Bob 生成密钥对
    b_pri, b_pub = generate_keys()

    m = "Hello, Proxy Re-Encryption!"
    print("origin message:", m)

    # Alice 加密消息，得到密文和 Capsule
    cipher_text, capsule = recrypt.encrypt(m, a_pub)

    # 对 Capsule 进行序列化、反序列化测试
    capsule_bytes = recrypt.encode_capsule(capsule)
    capsule_test = recrypt.decode_capsule(capsule_bytes)
    print("capsule before encode:", capsule)
    print("capsule after decode:", capsule_test)
    print("cipherText:", cipher_text.hex())

    # 使用 Alice 私钥重建 AES 密钥
    key_bytes = recrypt.recreate_aes_key_by_my_pri(capsule, a_pri)
    print("recreate key:", key_bytes.hex())

    # Alice 生成重加密密钥
    rk, pubX = recrypt.re_key_gen(a_pri, b_pub)
    print("rk:", rk)

    # 服务器执行重加密
    new_capsule = recrypt.re_encryption(rk, capsule)

    # Bob 使用重加密后的 Capsule 解密密文
    plain_text = recrypt.decrypt(b_pri, new_capsule, pubX, cipher_text)
    print("plainText:", plain_text.decode())

    # 使用 Alice 自己的私钥解密
    plain_text_by_my = recrypt.decrypt_on_my_pri(a_pri, capsule, cipher_text)
    print("PlainText by my own private key:", plain_text_by_my.decode())

    # 文件加密/解密示例（文件 a.txt 需存在）
    # file_capsule = recrypt.encrypt_file("a.txt", "a_encrypt.txt", a_pub)
    # file_new_capsule = recrypt.re_encryption(rk, file_capsule)
    # recrypt.decrypt_file("a_encrypt.txt", "a_decrypt.txt", b_pri, file_new_capsule, pubX)


if __name__ == "__main__":
    main()
