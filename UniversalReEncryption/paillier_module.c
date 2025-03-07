#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <math.h>
#include <gmp.h>

// 辅助函数 L(u) = (u-1) // n
static void _L(mpz_t result, mpz_t u, mpz_t n) {
    mpz_sub_ui(u, u, 1);
    mpz_div(result, u, n);
}

// 判断一个整数 n 是否为素数
static int _is_prime(mpz_t n) {
    return mpz_probab_prime_p(n, 10);
}

// 生成一个大致 bits 位的素数
static mpz_t _generate_prime(int bits) {
    mpz_t num;
    mpz_init(num);
    while (1) {
        mpz_rrandomb(num, gmp_randstate, bits);
        mpz_setbit(num, bits - 1);
        mpz_setbit(num, 0);
        if (_is_prime(num)) {
            return num;
        }
    }
}

// 生成 Paillier 密钥对
static void _generate_paillier_keys(int bits, mpz_t *public_key, mpz_t *private_key) {
    mpz_t p, q, n, n_sq, lam, g, u, mu;
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(n_sq);
    mpz_init(lam);
    mpz_init(g);
    mpz_init(u);
    mpz_init(mu);

    p = _generate_prime(bits);
    q = _generate_prime(bits);
    while (mpz_cmp(p, q) == 0) {
        q = _generate_prime(bits);
    }

    mpz_mul(n, p, q);
    mpz_pow_ui(n_sq, n, 2);
    mpz_mul(lam, p - 1, q - 1);
    mpz_divexact(lam, lam, mpz_gcd(p - 1, q - 1));

    g = mpz_add_ui(n, 1);

    mpz_powm(u, g, lam, n_sq);
    _L(u, u, n);
    mpz_invert(mu, u, n);

    mpz_set(public_key[0], n);
    mpz_set(public_key[1], g);
    mpz_set(private_key[0], lam);
    mpz_set(private_key[1], mu);
}

// Paillier 加密
static mpz_t encrypt(mpz_t m, mpz_t *public_key) {
    mpz_t n, g, r, n_sq, c;
    mpz_init(n);
    mpz_init(g);
    mpz_init(r);
    mpz_init(n_sq);
    mpz_init(c);

    n = public_key[0];
    g = public_key[1];
    mpz_pow_ui(n_sq, n, 2);

    while (1) {
        mpz_urandomm(r, gmp_randstate, n);
        if (mpz_gcd(r, n) == 1) {
            break;
        }
    }

    mpz_powm(c, g, m, n_sq);
    mpz_powm(r, r, n, n_sq);
    mpz_mul(c, c, r);
    mpz_mod(c, c, n_sq);

    return c;
}

// Paillier 解密
static mpz_t decrypt(mpz_t c, mpz_t *private_key, mpz_t *public_key) {
    mpz_t n, lam, mu, n_sq, u, L_u, m;
    mpz_init(n);
    mpz_init(lam);
    mpz_init(mu);
    mpz_init(n_sq);
    mpz_init(u);
    mpz_init(L_u);
    mpz_init(m);

    n = public_key[0];
    lam = private_key[0];
    mu = private_key[1];
    mpz_pow_ui(n_sq, n, 2);

    mpz_powm(u, c, lam, n_sq);
    _L(L_u, u, n);
    mpz_mul(m, L_u, mu);
    mpz_mod(m, m, n);

    return m;
}

// 重加密操作
static mpz_t reencrypt(mpz_t c, mpz_t *public_key) {
    mpz_t n, n_sq, c0;
    mpz_init(n);
    mpz_init(n_sq);
    mpz_init(c0);

    n = public_key[0];
    mpz_pow_ui(n_sq, n, 2);

    c0 = encrypt(mpz_t(0), public_key);
    mpz_mul(c, c, c0);
    mpz_mod(c, c, n_sq);

    return c;
}

// 模块方法定义
static PyMethodDef PaillierMethods[] = {
    {"encrypt", (PyCFunction)encrypt, METH_VARARGS, "Encrypt a message using Paillier"},
    {"decrypt", (PyCFunction)decrypt, METH_VARARGS, "Decrypt a ciphertext using Paillier"},
    {"reencrypt", (PyCFunction)reencrypt, METH_VARARGS, "Re-encrypt a ciphertext"},
    {NULL, NULL, 0, NULL}
};

// 模块定义
static struct PyModuleDef pailliermodule = {
    PyModuleDef_HEAD_INIT,
    "paillier",
    NULL,
    -1,
    PaillierMethods
};

// 模块初始化
PyMODINIT_FUNC PyInit_paillier(void) {
    return PyModule_Create(&pailliermodule);
}

//#include<gmp.h>
//#define N 1212
//int test01()
//{
//    mpz_t a,c;
//    mpz_init(a);
//    mpz_init(c);
//
//    mpz_init_set_ui(a, 2);
//    mpz_pow_ui(c, a, N);
//    gmp_printf("2^%d = %Zd\n", N, c);
//
//    mpz_clear(a);
//    mpz_clear(c);
//    return 0;
//}
//
//static struct PyModuleDef pailliermodule = {
//    PyModuleDef_HEAD_INIT,
//    "test01",
//    NULL,
//    -1,
//    NULL
//};
//
//PyMODINIT_FUNC PyInit_paillier(void) {
//    return PyModule_Create(&pailliermodule);
//}