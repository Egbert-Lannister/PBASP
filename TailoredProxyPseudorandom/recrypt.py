# recrypt.py
import pickle
from curve import generate_keys, point_scalar_mul, point_scalar_add, point_to_bytes, CURVE, N
import utils
import math_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ecdsa import VerifyingKey

class Capsule:
    def __init__(self, E, V, s):
        self.E = E  # E 为 VerifyingKey（公钥）
        self.V = V  # 同上
        self.s = s  # 整数

    def __repr__(self):
        return f"Capsule(E={utils.public_key_to_string(self.E)}, V={utils.public_key_to_string(self.V)}, s={self.s})"

def encrypt_key_gen(pub_key):
    """
    加密过程的密钥生成：
      - 随机生成 E,V 密钥对
      - 计算 h = H2(E||V)
      - s = priV + priE * h (mod N)
      - 计算 point = pub_key^(priE + priV)
      - AES 密钥 = sha3(point_to_bytes(point))
    """
    priE, pubE = generate_keys()
    priV, pubV = generate_keys()
    h_data = utils.concat_bytes(point_to_bytes(pubE), point_to_bytes(pubV))
    h = utils.hash_to_curve(utils.sha3_hash(h_data))
    s = math_utils.big_int_add(priV.privkey.secret_multiplier,
                               math_utils.big_int_mul(priE.privkey.secret_multiplier, h))
    total_scalar = priE.privkey.secret_multiplier + priV.privkey.secret_multiplier
    point = point_scalar_mul(pub_key.pubkey.point, total_scalar)
    key_bytes = utils.sha3_hash(point_to_bytes(point))
    capsule = Capsule(pubE, pubV, s)
    print("old key:", key_bytes.hex())
    return capsule, key_bytes

def recreate_aes_key_by_my_pri(capsule, a_pri):
    """
    使用自己的私钥重建 AES 密钥：
      - 计算 point1 = E + V
      - 计算 point = point1 * (a_pri)
      - AES 密钥 = sha3(point_to_bytes(point))
    """
    point1 = point_scalar_add(capsule.E.pubkey.point, capsule.V.pubkey.point)
    point = point_scalar_mul(point1, a_pri.privkey.secret_multiplier)
    key_bytes = utils.sha3_hash(point_to_bytes(point))
    return key_bytes

def encrypt_message_by_aes_key(message, key_bytes):
    """
    使用 AES-GCM 对消息加密：
      - 将 key_bytes 转为十六进制字符串
      - 使用前 32 个字符（16 字节）作为 AES 密钥，使用 key_bytes 前 12 字节作为 nonce
    """
    full_key = key_bytes.hex()  # 长度 64 字符（32 字节）
    aes_key = bytes.fromhex(full_key[:32])
    nonce = key_bytes[:12]
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, message.encode(), None)
    return ct

def encrypt(message, pub_key):
    capsule, key_bytes = encrypt_key_gen(pub_key)
    ct = encrypt_message_by_aes_key(message, key_bytes)
    return ct, capsule

def re_key_gen(a_pri, b_pub):
    """
    生成重加密密钥：
      - 生成随机密钥对 (priX, pubX)
      - 计算 point = b_pub^(priX)
      - d = H3(pubX || b_pub || point)
      - rk = a_pri * d^(-1) mod N
    """
    priX, pubX = generate_keys()
    point = point_scalar_mul(b_pub.pubkey.point, priX.privkey.secret_multiplier)
    d_data = utils.concat_bytes(point_to_bytes(pubX), point_to_bytes(b_pub))
    d_data = utils.concat_bytes(d_data, point_to_bytes(point))
    d = utils.hash_to_curve(utils.sha3_hash(d_data))
    inv_d = math_utils.get_invert(d)
    rk = math_utils.big_int_mul(a_pri.privkey.secret_multiplier, inv_d) % N
    return rk, pubX

def _scale_public_key(vk, scalar):
    """
    将 VerifyingKey 乘以标量，返回新的 VerifyingKey
    """
    point = vk.pubkey.point * scalar
    x_bytes = point.x().to_bytes(32, 'big')
    y_bytes = point.y().to_bytes(32, 'big')
    pub_bytes = x_bytes + y_bytes
    return VerifyingKey.from_string(pub_bytes, curve=CURVE)

# 将 _scale_public_key 作为 Capsule 的静态方法使用
Capsule._scale_public_key = staticmethod(_scale_public_key)

def re_encryption(rk, capsule):
    """
    服务器重加密：
      - 检查 g^s 是否等于 V + E^(H2(E||V))
      - 如果校验通过，则计算 E' = E^rk, V' = V^rk
    """
    generator = CURVE.generator
    left_point = generator * capsule.s

    h_data = utils.concat_bytes(point_to_bytes(capsule.E), point_to_bytes(capsule.V))
    h_val = utils.hash_to_curve(utils.sha3_hash(h_data))
    e_h = point_scalar_mul(capsule.E.pubkey.point, h_val)
    right_point = point_scalar_add(capsule.V.pubkey.point, e_h)
    if left_point != right_point:
        raise ValueError("Capsule not match")
    new_E = Capsule._scale_public_key(capsule.E, rk)
    new_V = Capsule._scale_public_key(capsule.V, rk)
    new_capsule = Capsule(new_E, new_V, capsule.s)
    return new_capsule

def decrypt_key_gen(b_pri, capsule, pubX):
    """
    解密时，先重建 AES 密钥：
      - S = pubX^(b_pri)
      - d = H3(pubX || b_pri.public_key || S)
      - key = sha3( (E+V)^d )
    """
    S_point = pubX.pubkey.point * b_pri.privkey.secret_multiplier
    b_pub = b_pri.get_verifying_key()
    d_data = utils.concat_bytes(point_to_bytes(pubX), point_to_bytes(b_pub))
    d_data = utils.concat_bytes(d_data, point_to_bytes(S_point))
    d = utils.hash_to_curve(utils.sha3_hash(d_data))
    point = point_scalar_mul(point_scalar_add(capsule.E.pubkey.point, capsule.V.pubkey.point), d)
    key_bytes = utils.sha3_hash(point_to_bytes(point))
    return key_bytes

def decrypt(b_pri, capsule, pubX, cipher_text):
    key_bytes = decrypt_key_gen(b_pri, capsule, pubX)
    full_key = key_bytes.hex()
    aes_key = bytes.fromhex(full_key[:32])
    nonce = key_bytes[:12]
    aesgcm = AESGCM(aes_key)
    plain = aesgcm.decrypt(nonce, cipher_text, None)
    return plain

def decrypt_on_my_pri(a_pri, capsule, cipher_text):
    key_bytes = recreate_aes_key_by_my_pri(capsule, a_pri)
    full_key = key_bytes.hex()
    aes_key = bytes.fromhex(full_key[:32])
    nonce = key_bytes[:12]
    aesgcm = AESGCM(aes_key)
    plain = aesgcm.decrypt(nonce, cipher_text, None)
    return plain

def encode_capsule(capsule):
    """
    使用 pickle 序列化 Capsule 对象，
    注意：将公钥转换为十六进制字符串保存
    """
    data = {
        'E': utils.public_key_to_string(capsule.E),
        'V': utils.public_key_to_string(capsule.V),
        's': capsule.s
    }
    return pickle.dumps(data)

def decode_capsule(data_bytes):
    data = pickle.loads(data_bytes)
    E = VerifyingKey.from_string(bytes.fromhex(data['E'])[1:], curve=CURVE)
    V = VerifyingKey.from_string(bytes.fromhex(data['V'])[1:], curve=CURVE)
    s = data['s']
    return Capsule(E, V, s)

def ofb_file_encrypt(key_bytes, iv, infile_name, outfile_name):
    """
    使用 AES OFB 模式加密文件
    """
    key = key_bytes[:32]
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    encryptor = cipher.encryptor()
    with open(infile_name, "rb") as fin, open(outfile_name, "wb") as fout:
        while True:
            chunk = fin.read(1024)
            if not chunk:
                break
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())

def ofb_file_decrypt(key_bytes, iv, infile_name, outfile_name):
    """
    使用 AES OFB 模式解密文件
    """
    key = key_bytes[:32]
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    decryptor = cipher.decryptor()
    with open(infile_name, "rb") as fin, open(outfile_name, "wb") as fout:
        while True:
            chunk = fin.read(1024)
            if not chunk:
                break
            fout.write(decryptor.update(chunk))
        fout.write(decryptor.finalize())

def encrypt_file(input_file, output_file, pub_key):
    capsule, key_bytes = encrypt_key_gen(pub_key)
    iv = key_bytes[:16]
    ofb_file_encrypt(key_bytes, iv, input_file, output_file)
    return capsule

def decrypt_file(input_file, output_file, b_pri, capsule, pubX):
    key_bytes = decrypt_key_gen(b_pri, capsule, pubX)
    iv = key_bytes[:16]
    ofb_file_decrypt(key_bytes, iv, input_file, output_file)
