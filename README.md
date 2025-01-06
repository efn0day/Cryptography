# Cryptography Overview

## What is Cryptography?
Cryptography is a branch of science that addresses issues related to information security. It deals with topics like confidentiality, integrity, and authentication by focusing on the encryption (coding) and decryption (decoding) of messages. This ensures that the transmitted messages can only be understood by the intended recipient and prevents third parties from reading or altering the messages.

Cryptography has a long history that dates back to ancient times. It is believed to have started in 4000 B.C., with symbols used on papyrus in Egypt. Today, cryptography is still widely used in military, government, banking, e-commerce, and many other industrial sectors.

## Encryption Methods

Encryption is a method used to make data unreadable. It is essential for the security of data. Encryption can be done in two main ways: symmetric and asymmetric.

### Symmetric Encryption

Symmetric encryption is a method where the same key is used for both encryption and decryption processes. The security of encrypted data in this method depends directly on the security of the key. If the key is compromised, all the data can be exposed.

```js
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
Asymmetric Encryption
Asymmetric encryption, also known as public-key encryption, is a different approach. In this method, two different keys are used: a public key and a private key.

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
Advanced Encryption Methods
Advanced encryption methods are more robust and provide a higher level of security than basic methods. These methods often use complex mathematical operations and algorithms.

Block Cipher
Block cipher is performed by dividing a message into segments and encrypting each segment separately. In this method, the size of the message blocks is defined, and encryption is applied to the block sizes. For instance, the AES encryption method encrypts 128-bit blocks.

Stream Cipher
Stream cipher encrypts individual bits instead of dividing the message into segments. In this method, the encryption key is applied bit by bit, and the encryption process is completed by encrypting each bit.

Hash Functions
Hash functions generate a fixed-size output from a given message. This output can serve as a fingerprint and plays a vital role in maintaining the integrity of the message.

js
Kodu kopyala
const crypto = require('crypto');

const message = 'Hello World!';

const hash = crypto.createHash('sha256');
hash.update(message);

const hash_hex = hash.digest('hex');

console.log(hash_hex);
Cryptography in This Project
The method in this project allows encryption of a given text or encrypted text by converting the text characters into specific numerical values. Similarly, the reverse process decrypts the text to retrieve the original message.

Encryption Method
The encryption process involves mapping each character to a specific numerical value based on its alphabetical position.

Decryption Method
The decryption process takes the numerical values from the encrypted text and maps them back to characters based on the mappings in the array.

Usage
This method can be used as a simple encryption technique. However, it is not sufficient as a secure method, especially for sensitive data.
