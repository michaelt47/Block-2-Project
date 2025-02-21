# AES-256 Encryptor/Decryptor

<a name="basic-functionality"></a>
## Basic Functionality

The encryption/decryption methods used are implemented through the OpenSSL library. 

**_Note: this can only be ran on mac machines with touch ID_**

### Encryptor

The program `encryptor` asks a user to provide input that is stored into a map of type `map<string, double>`. 
This map is then serialized to a string and then encrypted with a user provided password that is hashed to a 256-bit
key and fed to the OpenSSL AES-256 encryption algorithm. This outputs a string that is then written to a file with 
the name of the file being provided by the user.

### Decryptor

The program `decryptor` requires a file be passed in when running using `./decryptor filename.txt` where filename.txt is
the name of an encrypted file. When the program runs, it prompts the user to authenticate that they own the device containing
the file through touch ID. The implementation of the touch ID authentication is done through macOS's LocalAuthentication framework.
If the authentication is successful, the user must then provide the password that was used to encrypt the file to then
decrypt the file. The outputs of the decryption are stored in a string which is then printed to the shell.

## Installation and Usage

The source code can be downloaded by going to https://github.com/michaelt47/Block-2-Project and clicking the green "Code" button,
then downloading a zip of the source code. After extracting the zip file, you must install OpenSSL with Homebrew. 

*(If you do not already have Homebrew installed, instructions to install it can be found here: https://docs.brew.sh/Installation)*

Although OpenSSL is likely to already be installed on your mac, it is best to run this command: 
`brew install openssl`

### Compilation

Once OpenSSL is installed, open a terminal window and navigate to the directory where the source code has been extracted.
To compile the encryptor, run: 

`clang++ -std=c++17 encryptor.cpp -o encryptor -I/opt/homebrew/include -L/opt/homebrew/lib -lssl -lcrypto`

To compile the decryptor, run: 

`clang++ -std=c++17 decryptor.mm -o decryptor -framework Foundation -framework LocalAuthentication -I/opt/homebrew/include -L/opt/homebrew/lib -lssl -lcrypto`

If there are issues accessing the Apple Framework, XCode may need to be installed on your machine.

### Running encryptor/decryptor

`encryptor` can be ran with `./encryptor`

`decryptor` can be ran with `./decryptor filename`

More extensive usage instructions [can be found in Basic Functionality](#basic-functionality)

## Limitations

encryptor is designed to only take in user input to fill a map. This is highly limiting as it doesn't allow the user to
encrypt other types of data or even whole files. However, this could be easily redesigned in order to encrypt files and/or
other types of data.

decryptor only outputs decrypted file data to the shell, which could be redirected to a file in the shell, or the decryptor
could be redesigned to only output decrypted data to a file. 

The touch ID functionality in decryptor is also quite basic, and only prevents attacks on data if the attacker
is using the owner's machine. For certain offline or closed-networked systems, this can be highly useful, but if
an attacker is able to steal the encrypted file, if they have the password there will be no other security method to keep them
from decrypting the file other than the AES key. 

For AES-256, as far as encryption technology goes, this is one of the best encryption methods. Brute force attacks on AES-256 encrypted data are
not very feasible, and no technology (except for maybe quantum computers) seem close to being able to brute force the decryption.
More information on AES-256 encryption can be found here: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

Another limitation with this method of encryption is the requirement that the passwords or keys are managed by the user
in some way. If a password is lost, the encrypted data will likely be unable to be accessed. 
AES algorithms are also computationally intensive and may have issues running on older systems or embedded systems.

## Responsible Use

Encryption is famously used in ransomware attacks. These attacks usually require a sum of money be paid in order to gain
access to the decryption key to decrypt files stored on a computer. These attacks can be especially dangerous because 
the hacking software could be designed to delete all of the encrypted files in the case that a user enters the wrong decryption
password. Although this source code would be an easy starting point to create ransomware, this sort of ransomware should **never** be created with ill-intent.

If you decide to use this method to encrypt your files, responsible use will include managing passwords to each of your encrypted files
in a secure way. If someone is able to retrieve your encrypted files and has your password, they will likely be able to decrypt the file.








