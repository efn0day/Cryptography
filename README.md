What is Cryptography?
Cryptography is a branch of science that addresses issues related to information security. It deals with topics like confidentiality, integrity, and authentication by focusing on the encryption (coding) and decryption (decoding) of messages. This ensures that the transmitted messages can only be understood by the intended recipient and prevents third parties from reading or altering the messages.

Cryptography has a long history that dates back to ancient times. It is believed to have started in 4000 B.C., with symbols used on papyrus in Egypt. Today, cryptography is still widely used in military, government, banking, e-commerce, and many other industrial sectors.

<br /><br />

Encryption Methods
Encryption is a method used to make data unreadable. It is essential for the security of data. Encryption can be done in two main ways: symmetric and asymmetric.

<br />
Symmetric Encryption
Symmetric encryption is a method where the same key is used for both encryption and decryption processes. The security of encrypted data in this method depends directly on the security of the key. If the key is compromised, all the data can be exposed.

js
Kodu kopyala
const crypto = require('crypto');

const secretKey = 'mySecretKey';
const data = 'Hello, world!';

const cipher = crypto.createCipheriv('des-ede3', secretKey, null);
let encryptedData = cipher.update(data, 'utf8', 'hex');
encryptedData += cipher.final('hex');

console.log('Encrypted Data:', encryptedData);

const decipher = crypto.createDecipheriv('des-ede3', secretKey, null);
let decryptedData = decipher.update(encryptedData, 'hex', 'utf8');
decryptedData += decipher.final('utf8');

console.log('Decrypted Data:', decryptedData);
<br />
Asymmetric Encryption
Asymmetric encryption, also known as public-key encryption, is a different approach. In this method, two different keys are used: a public key and a private key.

The public key can be known by everyone and is used by anyone to encrypt messages. The private key, however, is known only to the recipient and is used to decrypt the messages.

Asymmetric encryption uses mathematical operations for encrypting and decrypting messages. These operations usually involve large numbers, and the encryption and decryption processes can be relatively slow. However, this method is more secure and is commonly used for processes like mutual authentication.

The most common application of asymmetric encryption is in protocols like SSL (Secure Sockets Layer) and TLS (Transport Layer Security), which ensure secure information exchange over the internet.

js
Kodu kopyala
const crypto = require('crypto');

crypto.generateKeyPair('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
    }
}, (err, publicKey, privateKey) => {
    if (err) throw err;
    let message = Buffer.from('Hello World');
    let encryptedMessage = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, message);

    let decryptedMessage = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, encryptedMessage);

    console.log(decryptedMessage.toString());
});
<br /><br />

Advanced Encryption Methods
Advanced encryption methods are more robust and provide a higher level of security than basic methods. These methods often use complex mathematical operations and algorithms.

Some of the advanced encryption methods include AES (Advanced Encryption Standard), Blowfish, Twofish, Serpent, and Camellia.

<br />
Block Cipher
Block cipher is performed by dividing a message into segments and encrypting each segment separately. In this method, the size of the message blocks is defined, and encryption is applied to the block sizes. For instance, the AES encryption method encrypts 128-bit blocks.

The security of block cipher methods depends on factors like the encryption algorithm used and the block size. The larger the block size, the higher the security level. However, larger block sizes increase the processing time.

<br />
Stream Cipher
Stream cipher encrypts individual bits instead of dividing the message into segments. In this method, the encryption key is applied bit by bit, and the encryption process is completed by encrypting each bit.

Stream cipher methods allow the encryption process to proceed at the same speed, regardless of the message length. However, key management is more complex, and the security depends on the encryption algorithm and key management.

<br />
Hash Functions
Hash functions generate a fixed-size output from a given message. This output can serve as a fingerprint and plays a vital role in maintaining the integrity of the message.

The most significant feature of hash functions is that even the slightest change in the message results in a substantial difference in the output. Therefore, hash functions are widely used in verifying message integrity, authenticating messages, and generating encryption keys.

For example, SHA-3 and SHA-256 hash functions generate fixed-size outputs from given messages.

js
Kodu kopyala
const crypto = require('crypto');

const message = 'Hello World!';

const hash = crypto.createHash('sha256');
hash.update(message);

const hash_hex = hash.digest('hex');

console.log(hash_hex);
In the example above, the "Hello World!" message is passed through a hash function using the SHA-256 algorithm, and the output is calculated. The output, in hex format, is displayed as c3b...b7.

<br /><br />

Simple Cryptography with JavaScript
JavaScript, a programming language used for developing web-based applications, can be used to perform simple encryption operations. For instance, a web form with input fields for a text and a keyword can be created. The form can also have "Encrypt Text" and "Decrypt Text" buttons to process the user's data. However, for real-world secure cryptography, specialized libraries are recommended.

To create a simple encryption example with JavaScript, follow these steps:

Use prompt() to get the text and keyword input from the user.
Convert both the text and keyword to their ASCII codes for each character.
For each character, add the ASCII codes of the text and keyword, and the result becomes the new ASCII code.
Convert the new ASCII code to a character using String.fromCharCode() to form the encrypted text.
Display the encrypted text using alert().
To decrypt the encrypted text, reverse the same process to get the original text.
This basic method is not a secure cryptography technique. It is only intended to demonstrate the concept and perform simple encryption operations.

<br />
<br />
Cryptography in This Project
The method in this project allows encryption of a given text or encrypted text by converting the text characters into specific numerical values. Similarly, the reverse process decrypts the text to retrieve the original message.

<br />
Encryption Method
The encryption process involves mapping each character to a specific numerical value based on its alphabetical position. These mappings are stored in an array. Each array element contains a character and its corresponding numerical value.

For example, the character 'A' is mapped to the numerical value 0, 'B' to 1, and so on.

During encryption, the characters of the text are converted into numerical values based on these mappings, resulting in an array of numerical values. These numbers are then combined in hexadecimal format and separated by a dash (-).

For instance, encrypting "HELLO" would result in "9-37-46-46-50".

<br />
Decryption Method
The decryption process takes the numerical values from the encrypted text and maps them back to characters based on the mappings in the array. The numbers are stored in a string in hexadecimal format and separated by the "-" character.

Each number corresponds to a character in the mappings, and the result is the characters of the text. These characters are combined to retrieve the original message.

For example, decrypting "9-37-46-46-50" would result in "HELLO".

<br />
Usage
This method can be used as a simple encryption technique. However, it is not sufficient as a secure method, especially for sensitive data. This is because the method uses a fixed numerical value for each character mapping, and the structure of the encrypted text is clearly visible. Therefore, it is important to use more secure encryption methods.
