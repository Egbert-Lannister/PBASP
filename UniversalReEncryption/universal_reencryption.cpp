#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <random>
#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <cmath>

namespace py = pybind11;
using boost::multiprecision::cpp_int;

// 扩展欧几里得算法求模逆元
cpp_int modinv(const cpp_int &a, const cpp_int &m) {
    cpp_int m0 = m, t, q;
    cpp_int x0 = 0, x1 = 1;
    cpp_int A = a, M = m;
    if (m == 1)
        return 0;
    while (A > 1) {
        q = A / M;
        t = M;
        M = A % M;
        A = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0)
        x1 += m0;
    return x1;
}

// 辅助函数 L(u) = (u-1)/n
cpp_int L_function(const cpp_int &u, const cpp_int &n) {
    return (u - 1) / n;
}

// 简单的素数判断（暴力检测，仅适用于位数较小的情况）
bool is_prime(const cpp_int &n) {
    if (n < 2)
        return false;
    // 将 n 转为 double（仅适用于较小数值）
    double nd = n.convert_to<double>();
    for (cpp_int i = 2; i <= static_cast<cpp_int>(std::sqrt(nd)); ++i) {
        if (n % i == 0)
            return false;
    }
    return true;
}

// 生成一个大致 bits 位的素数（暴力搜索，仅用于示例）
cpp_int generate_prime(int bits) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> bit_dist(0, 1);

    while (true) {
        cpp_int num = (cpp_int(1) << (bits - 1)) | 1; // 确保最高位与最低位为1
        for (int i = 1; i < bits - 1; i++) {
            if (bit_dist(gen) == 1)
                num |= (cpp_int(1) << i);
        }
        if (is_prime(num))
            return num;
    }
}

class UniversalReEncryption {
public:
    // 构造函数：生成 Paillier 密钥及分布式密钥（partial_key1, partial_key2）
    UniversalReEncryption(int security_param = 8) {
        generate_paillier_keys(security_param);
        // 分割私钥：示例中简单选取 partial_key1 = 2，partial_key2 = lam / 2
        partial_key1 = 2;
        partial_key2 = lam / partial_key1;
    }

    // 新增的用于 pickle 恢复的构造函数
    UniversalReEncryption(const std::string &n_str, const std::string &g_str,
                          const std::string &lam_str, const std::string &mu_str,
                          const std::string &partial_key1_str, const std::string &partial_key2_str)
        : n(n_str), g(g_str), lam(lam_str), mu(mu_str),
          partial_key1(partial_key1_str), partial_key2(partial_key2_str)
    {
        n_sq = n * n;  // 恢复 n_sq
    }

    // 加密：对明文 m 进行 Paillier 加密，返回密文 c
    cpp_int encrypt(const cpp_int &m) {
        cpp_int r = get_random_r();
        // c = g^m * r^n mod n^2
        cpp_int c = (boost::multiprecision::powm(g, m, n_sq) * boost::multiprecision::powm(r, n, n_sq)) % n_sq;
        return c;
    }

    // 解密：使用私钥 (lam, mu) 解密密文 c
    cpp_int decrypt(const cpp_int &c) {
        cpp_int u = boost::multiprecision::powm(c, lam, n_sq);
        cpp_int L_u = L_function(u, n);
        return (L_u * mu) % n;
    }

    // 重加密：对密文 c 生成一个加密 0 的密文，并与 c 相乘实现重新随机化
    cpp_int reencrypt(const cpp_int &c) {
        cpp_int c0 = encrypt(0);
        return (c * c0) % n_sq;
    }

    // 分布式解密第一步：部分解密
    cpp_int partial_decrypt(const cpp_int &c, const cpp_int &pkey) {
        return boost::multiprecision::powm(c, pkey, n_sq);
    }

    // 分布式解密第二步：利用另一部分密钥完成解密
    cpp_int final_decrypt(const cpp_int &c_partial, const cpp_int &pkey) {
        cpp_int c_full = boost::multiprecision::powm(c_partial, pkey, n_sq);
        cpp_int L_val = L_function(c_full, n);
        return (L_val * mu) % n;
    }

    // 对位图字符串中每一位 ('0' 或 '1') 进行加密，返回密文列表（字符串形式）
    std::vector<std::string> encrypt_bitmap(const std::string &bitmap_str) {
        std::vector<std::string> ciphertexts;
        for (char bit : bitmap_str) {
            int m = bit - '0';
            cpp_int c = encrypt(m);
            ciphertexts.push_back(c.str());
        }
        return ciphertexts;
    }

    // 对密文列表进行重加密，返回重加密后的密文列表（字符串形式）
    std::vector<std::string> reencrypt_bitmap(const std::vector<std::string> &ciphertexts) {
        std::vector<std::string> reencrypted;
        for (const auto &c_str : ciphertexts) {
            cpp_int c(c_str);
            cpp_int c_re = reencrypt(c);
            reencrypted.push_back(c_re.str());
        }
        return reencrypted;
    }

    // 分布式解密：对密文列表执行两阶段解密，返回解密后的位图字符串
    std::string decrypt_bitmap(const std::vector<std::string> &ciphertexts) {
        std::string result;
        for (const auto &c_str : ciphertexts) {
            cpp_int c(c_str);
            cpp_int c_partial = partial_decrypt(c, partial_key1);
            cpp_int m = final_decrypt(c_partial, partial_key2);
            result.push_back(static_cast<char>('0' + static_cast<int>(m)));
        }
        return result;
    }

    // 获取公钥 (n, g)
    std::pair<std::string, std::string> get_public_key() const {
        return { n.str(), g.str() };
    }

    // 获取私钥 (lam, mu)
    std::pair<std::string, std::string> get_private_key() const {
        return { lam.str(), mu.str() };
    }

    // 获取部分解密密钥
    std::string get_partial_key1() const { return partial_key1.str(); }
    std::string get_partial_key2() const { return partial_key2.str(); }

private:
    cpp_int n, g, lam, mu, n_sq;
    cpp_int partial_key1, partial_key2;

    // 生成 Paillier 密钥对
    void generate_paillier_keys(int bits) {
        cpp_int p = generate_prime(bits);
        cpp_int q = generate_prime(bits);
        while (q == p) {
            q = generate_prime(bits);
        }
        n = p * q;
        n_sq = n * n;
        // lam = lcm(p-1, q-1) = (p-1)*(q-1) / gcd(p-1, q-1)
        cpp_int p_minus = p - 1;
        cpp_int q_minus = q - 1;
        cpp_int gcd_val = boost::multiprecision::gcd(p_minus, q_minus);
        lam = (p_minus * q_minus) / gcd_val;
        g = n + 1;
        cpp_int u = boost::multiprecision::powm(g, lam, n_sq);
        cpp_int L_u = L_function(u, n);
        mu = modinv(L_u, n);
    }

    // 获取加密时所需的随机数 r（1 <= r < n 且 gcd(r, n) = 1）
    cpp_int get_random_r() {
        std::random_device rd;
        std::mt19937 gen(rd());
        cpp_int r;
        std::uniform_int_distribution<unsigned long long> dis(1, 1000);  // 这里数值范围仅作示例
        do {
            r = dis(gen);
        } while (boost::multiprecision::gcd(r, n) != 1);
        return r;
    }
};

/// 使用 pybind11 将 C++ 类包装为 Python 模块
PYBIND11_MODULE(universal_reencryption, m) {
    m.doc() = "UniversalReEncryption C++ 扩展模块（关键运算部分）";

    py::class_<UniversalReEncryption>(m, "UniversalReEncryption")
        .def(py::init<int>(), py::arg("security_param") = 8)
        // 新增 pickle 支持：定义 __getstate__ 和 __setstate__
        .def(py::pickle(
            // __getstate__
            [](const UniversalReEncryption &self) {
                return py::make_tuple(
                    self.get_public_key().first,    // n
                    self.get_public_key().second,   // g
                    self.get_private_key().first,   // lam
                    self.get_private_key().second,  // mu
                    self.get_partial_key1(),        // partial_key1
                    self.get_partial_key2()         // partial_key2
                );
            },
            // __setstate__
            [](py::tuple t) {
                if (t.size() != 6)
                    throw std::runtime_error("Invalid state!");
                return UniversalReEncryption(
                    t[0].cast<std::string>(),  // n
                    t[1].cast<std::string>(),  // g
                    t[2].cast<std::string>(),  // lam
                    t[3].cast<std::string>(),  // mu
                    t[4].cast<std::string>(),  // partial_key1
                    t[5].cast<std::string>()   // partial_key2
                );
            }
        ))
        .def("encrypt", [](UniversalReEncryption &ure, const py::int_ &m_val) {
            // 将传入的 py::int_ 转为字符串，再构造 cpp_int
            std::string m_str = py::str(m_val);
            cpp_int m(m_str);
            cpp_int result = ure.encrypt(m);
            std::string result_str = result.str();
            PyObject* py_long = PyLong_FromString(result_str.c_str(), nullptr, 10);
            return py::reinterpret_steal<py::int_>(py_long);
        })
        .def("decrypt", [](UniversalReEncryption &ure, const py::int_ &c_val) {
            std::string c_str = py::str(c_val);
            cpp_int c(c_str);
            cpp_int result = ure.decrypt(c);
            std::string result_str = result.str();
            PyObject* py_long = PyLong_FromString(result_str.c_str(), nullptr, 10);
            return py::reinterpret_steal<py::int_>(py_long);
        })
        .def("reencrypt", [](UniversalReEncryption &ure, const py::int_ &c_val) {
            std::string c_str = py::str(c_val);
            cpp_int c(c_str);
            cpp_int result = ure.reencrypt(c);
            std::string result_str = result.str();
            PyObject* py_long = PyLong_FromString(result_str.c_str(), nullptr, 10);
            return py::reinterpret_steal<py::int_>(py_long);
        })
        .def("partial_decrypt", [](UniversalReEncryption &ure, const py::int_ &c_val, const py::int_ &pkey) {
            std::string c_str = py::str(c_val);
            cpp_int c(c_str);
            std::string key_str = py::str(pkey);
            cpp_int key(key_str);
            cpp_int result = ure.partial_decrypt(c, key);
            std::string result_str = result.str();
            PyObject* py_long = PyLong_FromString(result_str.c_str(), nullptr, 10);
            return py::reinterpret_steal<py::int_>(py_long);
        })
        .def("final_decrypt", [](UniversalReEncryption &ure, const py::int_ &c_partial, const py::int_ &pkey) {
            std::string cp_str = py::str(c_partial);
            cpp_int cp(cp_str);
            std::string key_str = py::str(pkey);
            cpp_int key(key_str);
            cpp_int result = ure.final_decrypt(cp, key);
            std::string result_str = result.str();
            PyObject* py_long = PyLong_FromString(result_str.c_str(), nullptr, 10);
            return py::reinterpret_steal<py::int_>(py_long);
        })
        .def("encrypt_bitmap", &UniversalReEncryption::encrypt_bitmap)
        .def("reencrypt_bitmap", &UniversalReEncryption::reencrypt_bitmap)
        .def("decrypt_bitmap", &UniversalReEncryption::decrypt_bitmap)
        .def_property_readonly("public_key", &UniversalReEncryption::get_public_key)
        .def_property_readonly("private_key", &UniversalReEncryption::get_private_key)
        .def_property_readonly("partial_key1", &UniversalReEncryption::get_partial_key1)
        .def_property_readonly("partial_key2", &UniversalReEncryption::get_partial_key2);
}
