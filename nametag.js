const openpgp = require('openpgp')

class Nametag {

  static decryptAndVerify = (grantRequest, signingKey, decryptionKey) => {
    return Promise.all([
      openpgp.readMessage({armoredMessage: grantRequest}),
      openpgp.readKey({ armoredKey: signingKey}),
      openpgp.readPrivateKey({ armoredKey: decryptionKey})
    ])
    .then(([message, verificationKeys, decryptionKeys]) => {
      return openpgp.decrypt({
        message,
        decryptionKeys,
        expectSigned: true,
        verificationKeys // mandatory with expectSigned=true
      })
    })
  }

  static generateKeys = userIDs => openpgp.generateKey({userIDs})

}

module.exports = Nametag

//
// (async () => {
//     // put keys in backtick (``) to avoid errors caused by spaces or tabs
//     const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
// ...
// -----END PGP PUBLIC KEY BLOCK-----`;
//     const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
// ...
// -----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
//     const passphrase = `yourPassphrase`; // what the private key is encrypted with
//
//     const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
//
//     const privateKey = await openpgp.decryptKey({
//         privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
//         passphrase
//     });
//
//     const encrypted = await openpgp.encrypt({
//         message: await openpgp.createMessage({ text: 'Hello, World!' }), // input as Message object
//         encryptionKeys: publicKey,
//         signingKeys: privateKey // optional
//     });
//     console.log(encrypted); // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
//
//     const message = await openpgp.readMessage({
//         armoredMessage: encrypted // parse armored message
//     });
//     const { data: decrypted, signatures } = await openpgp.decrypt({
//         message,
//         verificationKeys: publicKey, // optional
//         decryptionKeys: privateKey
//     });
//     console.log(decrypted); // 'Hello, World!'
//     // check signature validity (signed messages only)
//     try {
//         await signatures[0].verified; // throws on invalid signature
//         console.log('Signature is valid');
//     } catch (e) {
//         throw new Error('Signature could not be verified: ' + e.message);
//     }
// })();
//
//
//
// (async () => {
//     const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
//         type: 'ecc', // Type of the key, defaults to ECC
//         curve: 'curve25519', // ECC curve name, defaults to curve25519
//         userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }], // you can pass multiple user IDs
//         passphrase: 'super long and hard to guess secret', // protects the private key
//         format: 'armored' // output key format, defaults to 'armored' (other options: 'binary' or 'object')
//     });
//
//     console.log(privateKey);     // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
//     console.log(publicKey);      // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
//     console.log(revocationCertificate); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
// })();
