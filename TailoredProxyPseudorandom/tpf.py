# tpf.py
from curve import N, point_to_bytes
import utils


def tpf(pk, m):
    """
    Tailored Proxy Pseudorandom Function (TPF)

    使用公钥 pk 和消息 m 生成伪随机字符串 ms，依赖于伪随机函数 F_G。

    算法步骤：
      1. 对消息 m 进行 SHA3-256 哈希，得到哈希值 h。
      2. 将 h 视为一个大整数 scalar，计算 scalar mod N（曲线阶）。
      3. 计算新的椭圆曲线点 P = pk * scalar（注意 pk 为椭圆曲线公钥，其点为 pk.pubkey.point）。
      4. 将 P 转换为字节串，再计算其 SHA3-256 哈希，输出即为伪随机字符串 ms。
    """
    # 1. 对消息 m 进行哈希
    m_hash = utils.sha3_hash(m.encode())
    # 2. 计算 scalar = int(m_hash) mod N
    scalar = int.from_bytes(m_hash, 'big') % N
    # 3. 计算 P = pk 的点乘以 scalar
    P = pk.pubkey.point * scalar
    # 4. 将 P 转换为字节串，并计算 SHA3-256 得到伪随机输出
    P_bytes = point_to_bytes(P)
    ms = utils.sha3_hash(P_bytes)
    return ms


# 示例测试
if __name__ == "__main__":
    from curve import generate_keys

    # 生成一个密钥对，取公钥
    sk, pk = generate_keys()
    message = "Test message for TPF"
    message2 = "Test message for TPF"
    ms = tpf(pk, message)
    print("TPF output:", ms.hex())
    ms2 = tpf(pk, message2)
    print("TPF output:", ms2.hex())
