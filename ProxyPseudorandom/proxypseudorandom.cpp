// proxypseudorandom.cpp
#include <pybind11/pybind11.h>
#include <pybind11/bytes.h>
#include <pybind11/stl.h>
#include <stdexcept>
#include <vector>
#include <sstream>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

namespace py = pybind11;

// 辅助：获取全局 EC_GROUP（NIST P-256 / prime256v1）
static EC_GROUP* get_group() {
    static EC_GROUP* group = nullptr;
    if (!group) {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group)
            throw std::runtime_error("Failed to create EC_GROUP");
    }
    return group;
}

// 将 OpenSSL 错误信息转换为字符串
std::string get_openssl_error() {
    char buf[256];
    ERR_error_string(ERR_get_error(), buf);
    return std::string(buf);
}

// 生成密钥对，返回 (私钥hex字符串, 公钥未压缩字节)
py::tuple generate_keys() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key)
        throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    if (!EC_KEY_generate_key(key)) {
        EC_KEY_free(key);
        throw std::runtime_error("EC_KEY_generate_key failed");
    }
    // 获取私钥（BIGNUM），转换为 hex 字符串
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(key);
    char *priv_hex = BN_bn2hex(priv_bn);
    std::string priv_str(priv_hex);
    OPENSSL_free(priv_hex);
    // 获取公钥点，并转换为未压缩字节 (0x04 + X + Y)
    const EC_POINT *pub_point = EC_KEY_get0_public_key(key);
    EC_GROUP *group = get_group();
    BN_CTX *ctx = BN_CTX_new();
    size_t len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> pub_bytes(len);
    if(EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub_bytes.data(), len, ctx) != len) {
        BN_CTX_free(ctx);
        EC_KEY_free(key);
        throw std::runtime_error("EC_POINT_point2oct failed");
    }
    BN_CTX_free(ctx);
    EC_KEY_free(key);
    return py::make_tuple(py::str(priv_str), py::bytes(reinterpret_cast<char*>(pub_bytes.data()), pub_bytes.size()));
}

// 使用 OpenSSL EVP 接口计算 SHA3-256（返回 32 字节散列）
py::bytes sha3_hash(py::bytes input) {
    std::string s = std::string(input);
    unsigned char hash[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if(1 != EVP_DigestUpdate(mdctx, s.data(), s.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    unsigned int out_len = 0;
    if(1 != EVP_DigestFinal_ex(mdctx, hash, &out_len)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    EVP_MD_CTX_free(mdctx);
    return py::bytes(reinterpret_cast<char*>(hash), out_len);
}

// 将 data 散列后映射到曲线上一个整数（mod N），返回 hex 字符串表示
py::str hash_to_curve(py::bytes data) {
    // 计算 SHA3-256
    py::bytes hash_bytes = sha3_hash(data);
    std::string hash_str = std::string(hash_bytes);
    BIGNUM *bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(hash_str.data()), hash_str.size(), NULL);
    if(!bn)
        throw std::runtime_error("BN_bin2bn failed in hash_to_curve");
    EC_GROUP *group = get_group();
    BIGNUM *order = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if(1 != EC_GROUP_get_order(group, order, ctx))
        throw std::runtime_error("EC_GROUP_get_order failed");
    if(1 != BN_mod(bn, bn, order, ctx))
        throw std::runtime_error("BN_mod failed");
    char *bn_hex = BN_bn2hex(bn);
    std::string ret(bn_hex);
    OPENSSL_free(bn_hex);
    BN_free(bn);
    BN_free(order);
    BN_CTX_free(ctx);
    return py::str(ret);
}

// 模运算加法 (a + b mod order)，输入 a,b 均为 hex 字符串，返回 hex 字符串
py::str big_int_add(py::str a_hex, py::str b_hex) {
    BIGNUM *a = NULL, *b = NULL, *res = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_hex2bn(&a, std::string(a_hex).c_str());
    BN_hex2bn(&b, std::string(b_hex).c_str());
    EC_GROUP *group = get_group();
    BIGNUM *order = BN_new();
    if(1 != EC_GROUP_get_order(group, order, ctx))
        throw std::runtime_error("EC_GROUP_get_order failed in big_int_add");
    BN_add(res, a, b);
    BN_mod(res, res, order, ctx);
    char *hex = BN_bn2hex(res);
    std::string ret(hex);
    OPENSSL_free(hex);
    BN_free(a); BN_free(b); BN_free(res); BN_free(order);
    BN_CTX_free(ctx);
    return py::str(ret);
}

// 模运算乘法 (a * b mod order)，输入 a,b 均为 hex 字符串，返回 hex 字符串
py::str big_int_mul(py::str a_hex, py::str b_hex) {
    BIGNUM *a = NULL, *b = NULL, *res = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_hex2bn(&a, std::string(a_hex).c_str());
    BN_hex2bn(&b, std::string(b_hex).c_str());
    EC_GROUP *group = get_group();
    BIGNUM *order = BN_new();
    if(1 != EC_GROUP_get_order(group, order, ctx))
        throw std::runtime_error("EC_GROUP_get_order failed in big_int_mul");
    BN_mul(res, a, b, ctx);
    BN_mod(res, res, order, ctx);
    char *hex = BN_bn2hex(res);
    std::string ret(hex);
    OPENSSL_free(hex);
    BN_free(a); BN_free(b); BN_free(res); BN_free(order);
    BN_CTX_free(ctx);
    return py::str(ret);
}

// 计算模逆元：返回 a^{-1} mod order（输入 a_hex 为 hex 字符串）
py::str get_invert(py::str a_hex) {
    BIGNUM *a = NULL;
    BN_hex2bn(&a, std::string(a_hex).c_str());
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = get_group();
    BIGNUM *order = BN_new();
    if(1 != EC_GROUP_get_order(group, order, ctx))
        throw std::runtime_error("EC_GROUP_get_order failed in get_invert");
    BIGNUM *inv = BN_mod_inverse(NULL, a, order, ctx);
    if (!inv)
        throw std::runtime_error("BN_mod_inverse failed: " + get_openssl_error());
    char *hex = BN_bn2hex(inv);
    std::string ret(hex);
    OPENSSL_free(hex);
    BN_free(a); BN_free(inv); BN_free(order);
    BN_CTX_free(ctx);
    return py::str(ret);
}

// 将公钥（以未压缩字节形式表示）乘以标量（hex字符串表示），返回新的公钥（未压缩字节）
py::bytes point_scalar_mul(py::bytes pub_key_bytes, py::str scalar_hex) {
    std::string pub_str = std::string(pub_key_bytes);
    const unsigned char* data = reinterpret_cast<const unsigned char*>(pub_str.data());
    size_t data_len = pub_str.size();
    EC_GROUP *group = get_group();
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *point = EC_POINT_new(group);
    if(1 != EC_POINT_oct2point(group, point, data, data_len, ctx)) {
        BN_CTX_free(ctx);
        EC_POINT_free(point);
        throw std::runtime_error("Failed to convert bytes to EC_POINT");
    }
    BIGNUM *scalar = NULL;
    BN_hex2bn(&scalar, std::string(scalar_hex).c_str());
    EC_POINT *new_point = EC_POINT_new(group);
    if(1 != EC_POINT_mul(group, new_point, NULL, point, scalar, ctx)) {
        BN_CTX_free(ctx);
        EC_POINT_free(point);
        EC_POINT_free(new_point);
        BN_free(scalar);
        throw std::runtime_error("EC_POINT_mul failed in point_scalar_mul");
    }
    // 转换 new_point 为未压缩字节
    size_t len = EC_POINT_point2oct(group, new_point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> out(len);
    if(EC_POINT_point2oct(group, new_point, POINT_CONVERSION_UNCOMPRESSED, out.data(), len, ctx) != len)
        throw std::runtime_error("EC_POINT_point2oct failed in point_scalar_mul");
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    EC_POINT_free(new_point);
    BN_free(scalar);
    return py::bytes(reinterpret_cast<char*>(out.data()), out.size());
}

// Capsule 重加密操作：输入重加密密钥 rk（hex字符串）和 capsule（字典：{"E": bytes, "V": bytes, "s": hex字符串}），返回新的 capsule 字典
py::dict re_encryption(py::str rk_hex, py::dict capsule) {
    // 取出 E 和 V（均为未压缩字节）
    py::bytes E_bytes = capsule["E"].cast<py::bytes>();
    py::bytes V_bytes = capsule["V"].cast<py::bytes>();
    // 这里简单地将 E, V 分别标量乘以 rk
    py::bytes new_E = point_scalar_mul(E_bytes, rk_hex);
    py::bytes new_V = point_scalar_mul(V_bytes, rk_hex);
    py::dict new_capsule;
    new_capsule["E"] = new_E;
    new_capsule["V"] = new_V;
    // s 保持不变
    new_capsule["s"] = capsule["s"];
    return new_capsule;
}

// 重加密密钥生成：输入 a_pri（hex字符串）和 b_pub（公钥，bytes），返回 (rk, pubX)
// 此处实现思路参照 Python 代码：生成随机密钥对 (priX, pubX)，计算 point = b_pub^(priX)，
// 并令 d = H3(pubX || b_pub || point)，最后 rk = a_pri * d^{-1} mod N
py::tuple re_key_gen(py::str a_pri_hex, py::bytes b_pub_bytes) {
    // 生成随机密钥对 (priX, pubX)
    auto keys = generate_keys();
    std::string priX_hex = keys[0].cast<std::string>();
    py::bytes pubX_bytes = keys[1].cast<py::bytes>();

    // 将 pubX 和 b_pub 以及 point = b_pub^(priX) 拼接散列
    EC_GROUP *group = get_group();
    BN_CTX *ctx = BN_CTX_new();

    // pubX 转 EC_POINT
    std::string pubX_str = std::string(pubX_bytes);
    const unsigned char *data_pubX = reinterpret_cast<const unsigned char*>(pubX_str.data());
    size_t pubX_len = pubX_str.size();
    EC_POINT *pubX = EC_POINT_new(group);
    if(1 != EC_POINT_oct2point(group, pubX, data_pubX, pubX_len, ctx)) {
         BN_CTX_free(ctx);
         EC_POINT_free(pubX);
         throw std::runtime_error("Failed to convert pubX bytes to EC_POINT");
    }
    // b_pub 转 EC_POINT
    std::string b_pub_str = std::string(b_pub_bytes);
    const unsigned char *data_bpub = reinterpret_cast<const unsigned char*>(b_pub_str.data());
    size_t bpub_len = b_pub_str.size();
    EC_POINT *b_pub = EC_POINT_new(group);
    if(1 != EC_POINT_oct2point(group, b_pub, data_bpub, bpub_len, ctx)) {
         BN_CTX_free(ctx);
         EC_POINT_free(pubX);
         EC_POINT_free(b_pub);
         throw std::runtime_error("Failed to convert b_pub bytes to EC_POINT");
    }
    // 将 priX_hex 转 BIGNUM
    BIGNUM *priX = NULL;
    BN_hex2bn(&priX, priX_hex.c_str());
    // 计算 point = b_pub^(priX)
    EC_POINT *point = EC_POINT_new(group);
    if(1 != EC_POINT_mul(group, point, NULL, b_pub, priX, ctx)) {
         BN_free(priX);
         BN_CTX_free(ctx);
         EC_POINT_free(pubX);
         EC_POINT_free(b_pub);
         EC_POINT_free(point);
         throw std::runtime_error("EC_POINT_mul failed in re_key_gen");
    }
    // 得到 pubX, b_pub, point 的未压缩字节并拼接
    int len_pubX = EC_POINT_point2oct(group, pubX, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> pubX_vec(len_pubX);
    EC_POINT_point2oct(group, pubX, POINT_CONVERSION_UNCOMPRESSED, pubX_vec.data(), len_pubX, ctx);

    int len_bpub = EC_POINT_point2oct(group, b_pub, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> bpub_vec(len_bpub);
    EC_POINT_point2oct(group, b_pub, POINT_CONVERSION_UNCOMPRESSED, bpub_vec.data(), len_bpub, ctx);

    int len_point = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> point_vec(len_point);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, point_vec.data(), len_point, ctx);

    std::vector<unsigned char> concat;
    concat.insert(concat.end(), pubX_vec.begin(), pubX_vec.end());
    concat.insert(concat.end(), bpub_vec.begin(), bpub_vec.end());
    concat.insert(concat.end(), point_vec.begin(), point_vec.end());

    // 计算 d = H3(concat)
    unsigned char d_hash[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(mdctx, concat.data(), concat.size());
    unsigned int d_len = 0;
    EVP_DigestFinal_ex(mdctx, d_hash, &d_len);
    EVP_MD_CTX_free(mdctx);
    // d 转 BIGNUM，并 mod order
    BIGNUM *d = BN_bin2bn(d_hash, d_len, NULL);
    BIGNUM *order = BN_new();
    if(1 != EC_GROUP_get_order(group, order, ctx))
         throw std::runtime_error("EC_GROUP_get_order failed in re_key_gen");
    if(1 != BN_mod(d, d, order, ctx))
         throw std::runtime_error("BN_mod failed in re_key_gen");
    // 计算 d 的逆元
    BIGNUM *inv_d = BN_mod_inverse(NULL, d, order, ctx);
    if(!inv_d)
         throw std::runtime_error("BN_mod_inverse failed in re_key_gen");
    // 将 a_pri_hex 转 BIGNUM
    BIGNUM *a_pri = NULL;
    BN_hex2bn(&a_pri, std::string(a_pri_hex).c_str());
    // rk = a_pri * inv_d mod order
    BIGNUM *rk = BN_new();
    BN_mul(rk, a_pri, inv_d, ctx);
    BN_mod(rk, rk, order, ctx);
    char *rk_hex_c = BN_bn2hex(rk);
    std::string rk_hex_str(rk_hex_c);
    OPENSSL_free(rk_hex_c);
    // 清理
    BN_free(priX);
    BN_free(d);
    BN_free(inv_d);
    BN_free(a_pri);
    BN_free(rk);
    BN_free(order);
    BN_CTX_free(ctx);
    EC_POINT_free(b_pub);
    EC_POINT_free(point);
    // 此处 pubX 作为重加密过程中的附带数据，返回其未压缩字节
    BN_CTX *ctx2 = BN_CTX_new();
    int pubX_len2 = EC_POINT_point2oct(group, pubX, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx2);
    std::vector<unsigned char> pubX_bytes_vec(pubX_len2);
    EC_POINT_point2oct(group, pubX, POINT_CONVERSION_UNCOMPRESSED, pubX_bytes_vec.data(), pubX_len2, ctx2);
    BN_CTX_free(ctx2);
    py::bytes pubX_py(reinterpret_cast<char*>(pubX_bytes_vec.data()), pubX_bytes_vec.size());
    EC_POINT_free(pubX);
    return py::make_tuple(py::str(rk_hex_str), pubX_py);
}

PYBIND11_MODULE(proxypseudorandom, m) {
    m.doc() = "C++ 实现的 ProxyPseudorandom 关键运算模块";
    m.def("generate_keys", &generate_keys, "生成 ECDSA 密钥对 (私钥, 公钥)");
    m.def("sha3_hash", &sha3_hash, "计算 SHA3-256 散列");
    m.def("hash_to_curve", &hash_to_curve, "将数据散列后映射到曲线上一个整数（mod N），返回 hex 字符串");
    m.def("big_int_add", &big_int_add, "大整数加法 (a+b mod N)");
    m.def("big_int_mul", &big_int_mul, "大整数乘法 (a*b mod N)");
    m.def("get_invert", &get_invert, "计算模逆元");
    m.def("point_scalar_mul", &point_scalar_mul, "EC 点与标量乘法 (返回未压缩字节)");
    m.def("re_key_gen", &re_key_gen, "生成重加密密钥，返回 (rk, pubX)");
    m.def("re_encryption", &re_encryption, "对 capsule 进行重加密");
}
