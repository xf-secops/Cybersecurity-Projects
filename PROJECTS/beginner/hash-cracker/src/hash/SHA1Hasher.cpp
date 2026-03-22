// ©AngelaMos | 2026
// SHA1Hasher.cpp

#include "src/hash/SHA1Hasher.hpp"
#include <array>
#include <iomanip>
#include <memory>
#include <openssl/evp.h>
#include <sstream>

std::string SHA1Hasher::hash(std::string_view input) const {
    auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);

    EVP_DigestInit_ex(ctx.get(), EVP_sha1(), nullptr);
    EVP_DigestUpdate(ctx.get(), input.data(), input.size());

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx.get(), digest.data(), &len);

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i) {
        hex << std::setw(2) << static_cast<int>(digest[i]);
    }
    return hex.str();
}
