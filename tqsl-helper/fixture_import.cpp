// Test-only importer for generated certificates. Never point this program at
// a user's normal TQSL data directory or pass it real station credentials.
#include <tqsllib.h>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {
std::string readFile(const char *path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}
std::string errorText(const char *where) {
    const char *detail = tqsl_getErrorString();
    return std::string(where) + (detail && *detail ? std::string(": ") + detail : " failed");
}
}

int main(int argc, char **argv) {
    if (argc != 6) {
        std::cerr << "usage: arap-tqsl-fixture-import DIRECTORY ROOT_PEM INTERMEDIATE_PEM KEYBUF_B64 LEAF_PEM\n";
        return 2;
    }
    const std::string root = readFile(argv[2]);
    const std::string intermediate = readFile(argv[3]);
    const std::string keybuf = readFile(argv[4]);
    const std::string leaf = readFile(argv[5]);
    if (root.empty() || intermediate.empty() || keybuf.empty() || leaf.empty()) {
        std::cerr << "fixture input is missing or empty\n";
        return 2;
    }
    if (tqsl_setDirectory(argv[1]) || tqsl_init()) {
        std::cerr << errorText("initialize isolated TQSL data directory");
        return 1;
    }
    if (tqsl_importKeyPairEncoded(nullptr, "root", nullptr, root.c_str())) {
        std::cerr << errorText("import synthetic root");
        return 1;
    }
    if (tqsl_importKeyPairEncoded(nullptr, "authorities", nullptr, intermediate.c_str())) {
        std::cerr << errorText("import synthetic intermediate");
        return 1;
    }
    if (tqsl_importKeyPairEncoded("N0CALL", "user", keybuf.c_str(), leaf.c_str())) {
        std::cerr << errorText("import synthetic callsign certificate");
        return 1;
    }
    std::cout << "imported generated N0CALL certificate into isolated TQSL data directory\n";
    return 0;
}
