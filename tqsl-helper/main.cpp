#include <tqsllib.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {
struct CertList {
    tQSL_Cert *items = nullptr;
    int count = 0;
    ~CertList() { if (items) tqsl_freeCertificateList(items, count); }
};
struct Signing {
    tQSL_Cert cert = nullptr;
    bool active = false;
    ~Signing() { if (active) tqsl_endSigning(cert); }
};
struct X509Free { void operator()(X509 *p) const { X509_free(p); } };
struct BioFree { void operator()(BIO *p) const { BIO_free(p); } };
using X509Ptr = std::unique_ptr<X509, X509Free>;
using BioPtr = std::unique_ptr<BIO, BioFree>;

std::string tqslError(const char *where) {
    const char *detail = tqsl_getErrorString();
    return std::string(where) + (detail && *detail ? std::string(": ") + detail : " failed");
}
bool readFrame(std::vector<unsigned char>& out, uint32_t max) {
    uint32_t n = 0;
    if (!std::cin.read(reinterpret_cast<char*>(&n), sizeof n) || n > max) return false;
    out.resize(n);
    return n == 0 || static_cast<bool>(std::cin.read(reinterpret_cast<char*>(out.data()), n));
}
bool writeFrame(const std::string& value) {
    if (value.empty() || value.size() > 65536) return false;
    uint32_t n = static_cast<uint32_t>(value.size());
    std::cout.write(reinterpret_cast<const char*>(&n), sizeof n);
    std::cout.write(value.data(), value.size());
    return static_cast<bool>(std::cout);
}
bool encodeCertificate(tQSL_Cert cert, std::string& pem) {
    char buffer[8192]{};
    if (tqsl_getCertificateEncoded(cert, buffer, sizeof buffer)) return false;
    pem.assign(buffer);
    return !pem.empty();
}
X509Ptr parseCertificate(const std::string& pem) {
    BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) return {};
    return X509Ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}
bool selfSigned(X509 *cert) {
    if (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) != 0) return false;
    EVP_PKEY *key = X509_get_pubkey(cert);
    if (!key) return false;
    int ok = X509_verify(cert, key);
    EVP_PKEY_free(key);
    return ok == 1;
}
bool buildChain(const std::string& leafPem, CertList& authorities, std::vector<std::string>& chain) {
    chain.push_back(leafPem);
    X509Ptr current = parseCertificate(leafPem);
    if (!current) return false;
    std::vector<X509Ptr> candidates;
    candidates.reserve(authorities.count);
    std::vector<std::string> candidatePEM;
    candidatePEM.reserve(authorities.count);
    for (int i = 0; i < authorities.count; ++i) {
        std::string encoded;
        if (!encodeCertificate(authorities.items[i], encoded)) continue;
        auto parsed = parseCertificate(encoded);
        if (parsed) { candidatePEM.push_back(std::move(encoded)); candidates.push_back(std::move(parsed)); }
    }
    for (int depth = 0; depth < 8 && !selfSigned(current.get()); ++depth) {
        bool found = false;
        for (size_t i = 0; i < candidates.size(); ++i) {
            X509 *issuer = candidates[i].get();
            if (X509_NAME_cmp(X509_get_issuer_name(current.get()), X509_get_subject_name(issuer)) != 0) continue;
            EVP_PKEY *key = X509_get_pubkey(issuer);
            if (!key) continue;
            int verified = X509_verify(current.get(), key);
            EVP_PKEY_free(key);
            if (verified != 1) continue;
            if (selfSigned(issuer)) return true; // trust anchor supplied independently by verifier
            chain.push_back(candidatePEM[i]);
            current = X509Ptr(X509_dup(issuer));
            found = true;
            break;
        }
        if (!found) return true; // include the available partial chain; verifier checks trust
    }
    return true;
}
void wipe(std::vector<unsigned char>& data) {
    volatile unsigned char *p = data.empty() ? nullptr : data.data();
    for (size_t i = 0; i < data.size(); ++i) p[i] = 0;
    data.clear();
}
}

int main(int argc, char **argv) {
    std::string callsign, serial, directory, resourceDirectory;
    bool listCertificates = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--callsign" && i + 1 < argc) callsign = argv[++i];
        else if (arg == "--serial" && i + 1 < argc) serial = argv[++i];
        else if (arg == "--directory" && i + 1 < argc) directory = argv[++i];
        else if (arg == "--resource-directory" && i + 1 < argc) resourceDirectory = argv[++i];
        else if (arg == "--list-certificates") listCertificates = true;
        else { std::cerr << "unknown or incomplete argument\n"; return 2; }
    }
    if (callsign.empty() || callsign.size() > TQSL_CALLSIGN_MAX) { std::cerr << "valid --callsign is required\n"; return 2; }
    if (!resourceDirectory.empty()) tQSL_RsrcDir = resourceDirectory.c_str();
    if (!directory.empty() && tqsl_setDirectory(directory.c_str())) { std::cerr << tqslError("set TQSL data directory"); return 1; }
    if (listCertificates) {
        if (tqsl_init()) { std::cerr << tqslError("TQSL initialization"); return 1; }
        CertList certificates;
        if (tqsl_selectCertificates(&certificates.items, &certificates.count, callsign.c_str(), 0, nullptr, nullptr, 0)) {
            std::cerr << tqslError("list callsign certificates"); return 1;
        }
        std::vector<std::string> serials;
        for (int i = 0; i < certificates.count; ++i) {
            char certCall[TQSL_CALLSIGN_MAX + 1]{};
            long certSerial = 0;
            if (tqsl_getCertificateCallSign(certificates.items[i], certCall, sizeof certCall) ||
                tqsl_getCertificateSerial(certificates.items[i], &certSerial)) continue;
            if (callsign == certCall && certSerial > 0) serials.push_back(std::to_string(certSerial));
        }
        if (serials.size() > 100) { std::cerr << "too many matching TQSL certificates"; return 1; }
        std::cout << "{\"certificates\":[";
        for (size_t i = 0; i < serials.size(); ++i) {
            if (i) std::cout << ',';
            std::cout << "{\"callsign\":\"" << callsign << "\",\"serial\":\"" << serials[i] << "\"}";
        }
        std::cout << "]}\n";
        return std::cout ? 0 : 1;
    }
    std::vector<unsigned char> password, challenge;
    if (!readFrame(password, TQSL_PASSWORD_MAX - 1) || !readFrame(challenge, 4096) || challenge.empty() || std::cin.peek() != EOF) {
        wipe(password); std::cerr << "invalid stdin framing\n"; return 2;
    }
    if (std::find(password.begin(), password.end(), 0) != password.end()) { wipe(password); std::cerr << "password contains NUL\n"; return 2; }
    if (tqsl_init()) { wipe(password); std::cerr << tqslError("TQSL initialization"); return 1; }
    CertList users;
    if (tqsl_selectCertificates(&users.items, &users.count, callsign.c_str(), 0, nullptr, nullptr, 0)) {
        wipe(password); std::cerr << tqslError("select callsign certificate"); return 1;
    }
    std::vector<int> matching;
    for (int i = 0; i < users.count; ++i) {
        char call[TQSL_CALLSIGN_MAX + 1]{};
        long certSerial = 0;
        if (tqsl_getCertificateCallSign(users.items[i], call, sizeof call) || tqsl_getCertificateSerial(users.items[i], &certSerial)) continue;
        if (callsign != call) continue;
        if (!serial.empty() && serial != std::to_string(certSerial)) continue;
        matching.push_back(i);
    }
    if (matching.size() != 1) {
        wipe(password);
        std::cerr << (matching.empty() ? "no current issued TQSL certificate matches callsign/serial" : "multiple TQSL certificates match; specify --serial");
        return 1;
    }
    tQSL_Cert selected = users.items[matching[0]];
    std::string leaf;
    if (!encodeCertificate(selected, leaf)) { wipe(password); std::cerr << tqslError("read public callsign certificate"); return 1; }
    Signing signing{selected, false};
    if (!password.empty()) password.push_back(0); // TQSLLIB expects a NUL-terminated password.
    char *passwordPtr = password.empty() ? nullptr : reinterpret_cast<char*>(password.data());
    if (tqsl_beginSigning(selected, passwordPtr, nullptr, nullptr)) {
        wipe(password); std::cerr << tqslError("unlock TQSL certificate"); return 1;
    }
    signing.active = true;
    int maxSize = 0;
    if (tqsl_getMaxSignatureSize(selected, &maxSize) || maxSize < 1 || maxSize > 4096) {
        wipe(password); std::cerr << tqslError("get TQSL signature size"); return 1;
    }
    std::vector<unsigned char> signature(maxSize);
    int signatureSize = maxSize;
    if (tqsl_signDataBlock(selected, challenge.data(), static_cast<int>(challenge.size()), signature.data(), &signatureSize) || signatureSize < 1 || signatureSize > maxSize) {
        wipe(password); std::cerr << tqslError("sign enrollment challenge"); return 1;
    }
    signature.resize(signatureSize);
    if (tqsl_endSigning(selected)) { wipe(password); std::cerr << tqslError("clear TQSL signing state"); return 1; }
    signing.active = false;
    wipe(password);
    CertList authorities;
    if (tqsl_selectCACertificates(&authorities.items, &authorities.count, "authorities")) {
        std::cerr << tqslError("load TQSL issuer certificates"); return 1;
    }
    std::vector<std::string> chain;
    if (!buildChain(leaf, authorities, chain) || chain.empty() || chain.size() > 8) {
        std::cerr << "unable to construct bounded TQSL certificate chain"; return 1;
    }
    std::cout.write("ARAPTQ1\n", 8);
    uint32_t sigSize = static_cast<uint32_t>(signature.size());
    std::cout.write(reinterpret_cast<const char*>(&sigSize), sizeof sigSize);
    std::cout.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    uint32_t count = static_cast<uint32_t>(chain.size());
    std::cout.write(reinterpret_cast<const char*>(&count), sizeof count);
    for (const auto& cert : chain) if (!writeFrame(cert)) { std::cerr << "certificate chain output error"; return 1; }
    return std::cout ? 0 : 1;
}
