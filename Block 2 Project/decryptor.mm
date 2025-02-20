#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#import <LocalAuthentication/LocalAuthentication.h>

/*
    AES Decryptor
    Built by Michael Timothy

    Feb 19th, 2025

    This decryptor implements an AES decryption method, which uses a password to decrypt data.

    Proper usage requires a user to run the file with "./decryptor file.txt" with file.txt being the name
    of any file that has been encrypted with our AES method.

    The user will be required to authenticate ownership of the computer with a TouchID authenticator.
    While this doesn't stop someone from writing their own decryption application and running it with the encrypted files,
    the main goal is to protect files directly on the owner's device and the TouchID is just a second line of defense
    along with the password required to decrypt the file.

    If the file is decrypted correctly, the decrypted data will be output to the shell.
*/



using namespace std;

string sha256(const string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);
    return string(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH);
}

string decryptAES(const string &ciphertext, const string &password) {
    unsigned char key[32]; // AES-256 requires a 256-bit key (32 bytes)
    string hashedPassword = sha256(password);
    memcpy(key, hashedPassword.data(), 32);

    // Extract IV from the beginning of the ciphertext
    if (ciphertext.size() < 16) {
        throw runtime_error("Ciphertext is too short");
    }

    unsigned char iv[16];
    memcpy(iv, ciphertext.data(), sizeof(iv));

    string encryptedText = ciphertext.substr(16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption");
    }

    string plaintext;
    plaintext.resize(encryptedText.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                          reinterpret_cast<const unsigned char*>(encryptedText.c_str()), encryptedText.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed");
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Final decryption step failed");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return plaintext;
}


class TouchIDAuthenticator {
public:
    // Function to perform authentication
    bool authenticate() {
        __block bool authenticationSuccess = false; // Store the result

        // Create an instance of LAContext
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;

        // Check if biometric authentication is available
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
            // Biometric authentication is available, prompt the user
            dispatch_semaphore_t semaphore = dispatch_semaphore_create(0); // To wait for async call

            [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                    localizedReason:@"Authenticate to proceed"
                                reply:^(BOOL success, NSError * _Nullable error) {
                if (success) {
                    authenticationSuccess = true;
                } else {
                    cerr << "Authentication failed: " 
                                << (error ? [[error localizedDescription] UTF8String] : "Unknown error") 
                                << endl;
                }
                dispatch_semaphore_signal(semaphore); // Release semaphore after completion
            }];

            // Wait for the async block to complete
            dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
        } else {
            // Biometric authentication is not available
            cerr << "Biometric authentication not available: "
                        << (error ? [[error localizedDescription] UTF8String] : "Unknown error")
                        << endl;
        }

        return authenticationSuccess;
    }
};


int main (int argc, char* argv[]) {
    // Get file to open
    if (argc != 2) {
        cerr << "This program requires 1 file to be passed in." << endl << "Example: ./decryptor file.txt" << endl;
        return 1;
    }

    string encryptedData;
    string password;

    // Extract data from file
    ifstream inputFile(argv[1], ios::binary);
    if (inputFile.is_open()) {
        inputFile.seekg(0, ios::end);
        size_t fileSize = inputFile.tellg();
        inputFile.seekg(0, ios::beg);

        encryptedData.resize(fileSize);
        inputFile.read(&encryptedData[0], fileSize);
        inputFile.close();
    } else {
        cerr << "Unable to open file " << argv[1] << endl;
        return 1;
    }


    // Authenticate with Touch ID
    cout << "Touch ID required to decrypt file" << endl;

    TouchIDAuthenticator authenticator;
    if (authenticator.authenticate()) {
        cout << "Authentication successful." << endl;
    } else {
        cout << "Authentication failed. User must be owner of the device in order to decrypt files." << endl;
        return 2;
    }

    // Decrypt the file and output the resulted string of data
    cout << "Enter decryption password:" << endl;
    getline(cin, password);

    string decryptedData = decryptAES(encryptedData, password);

    cout << decryptedData << endl;

    cout << "Process complete" << endl;
}