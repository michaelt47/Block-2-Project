#include <iostream>
#include <map>
#include <fstream>
#include <string>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;

/*
    AES Encryptor

    Built by Michael Timothy

    Feb 19th, 2025

    This program has a user input data into a C++ style map, and then encrypts the map data
    using an AES algorithm and a user provided password.

    The encrypted data is saved to a file with the filename being provided by the user.
*/

string serializeMapToString(const map<string, float>& mapData) {
    stringstream ss;
    
    for (const auto& [key, value] : mapData) {
        ss << key << ":" << value << "\n";
    }
    return ss.str();
};

std::string sha256(const std::string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);
    return std::string(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH);
}

std::string encryptAES(const std::string &plaintext, const std::string &password) {
    unsigned char key[32]; // AES-256 requires a 256-bit key (32 bytes)
    std::string hashedPassword = sha256(password);
    memcpy(key, hashedPassword.data(), 32);

    unsigned char iv[16]; // 16 bytes for AES-CBC IV
    if (!RAND_bytes(iv, sizeof(iv))) {
        throw std::runtime_error("Failed to generate random IV");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::string ciphertext;
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final encryption step failed");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);

    // Prepend IV to ciphertext for decryption
    return std::string(reinterpret_cast<char*>(iv), sizeof(iv)) + ciphertext;
}

int main () {
    map<string, float> userData;
    string input;

    while (true) {
        cout << "Enter a key and a value (or press enter to stop):" << endl;
        getline(cin, input);

        if (input.empty()) {break;}

        istringstream stream(input);
        string key;
        float value;

        if (stream >> key >> value) {
            userData[key] = value;
        } else {
            cout << "Invalid input." << endl;
        }
    }

    if (userData.empty()) {
        cout << "No data provided, terminating process" << endl;
        return 0;
    }

    string aesKey;
    string filename;

    string serializedData = serializeMapToString(userData);

    cout << "Enter password for file to be encrypted/decrypted with:" << endl;
    getline(cin, aesKey);

    string encryptedData = encryptAES(serializedData, aesKey);

    cout << "Enter filename to output encrypted data:" << endl;
    getline(cin, filename);

    ofstream outputFile(filename, ios::binary);

    if (outputFile.is_open()) {
        outputFile.write(encryptedData.data(), encryptedData.size()); // correctly handle data as binary
        cout << "Complete" << endl;  
    } else {
        cerr << "Unable to open file " << filename << endl;
        return 1;
    }

    return 0;
}



