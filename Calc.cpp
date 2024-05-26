#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <random>

int my_abs(int x) {
    return x < 0 ? -x : x;
}

uint64_t gcd(uint64_t a, uint64_t b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

uint64_t pollard_rho(uint64_t n) {
    if (n == 1) return 1;
    if (n % 2 == 0) return 2;

    uint64_t x = rand() % (n - 2) + 2;
    uint64_t y = x;
    uint64_t c = rand() % (n - 1) + 1;
    uint64_t d = 1;

    while (d == 1) {
        x = (x * x + c) % n;
        y = (y * y + c) % n;
        y = (y * y + c) % n;
        d = gcd(my_abs(x - y), n);
    }

    return d;
}

uint64_t generate_random_64bit_number() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    return dis(gen);
}

void prime_factorization(uint64_t n, uint64_t max_time) {
    std::srand(std::time(NULL));

    std::time_t start_time = std::time(NULL);

    std::cout << "开始分解质数 " << n << ":\n";

    while ((std::time(NULL) - start_time) < max_time) {
        uint64_t factor = pollard_rho(n);
        if (factor == 1 || factor == n) {
            std::cout << "无法分解质因数\n";
            break;
        }
        std::cout << factor << " ";
        std::cout.flush();

        n /= factor;
    }

    std::time_t end_time = std::time(NULL);
    std::cout << "\n总计用时 " << std::difftime(end_time, start_time) << " 秒\n";
    getchar();
}
