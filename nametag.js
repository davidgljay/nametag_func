import * as openpgp from 'openpgp'
import { imageHash } from 'image-hash'

class Nametag {

  static decrypt = (grantRequest, signingKey, decryptionKey) => {
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

  static encrypt = (text, signingKey, encryptionKey) => {
    return Promise.all([
      openpgp.createMessage({text}),
      openpgp.readPrivateKey({ armoredKey: signingKey}),
      openpgp.readKey({ armoredKey: encryptionKey})
    ])
    .then(([message, signingKeys, encryptionKeys]) => openpgp.encrypt({
        message,
        encryptionKeys,
        signingKeys
      })
    )
  }

  static sign = (text, signingKey) =>
    Promise.all([
      openpgp.createCleartextMessage({text}),
      openpgp.readPrivateKey({ armoredKey: signingKey})
    ])
    .then(([message, signingKeys]) => openpgp.sign({message, signingKeys}))

  static verify = (text, verificationKey) =>
          Promise.all([
            openpgp.readCleartextMessage({cleartextMessage: text}),
            openpgp.readKey({ armoredKey: verificationKey})
          ])
      .then(([message, verificationKeys]) => openpgp.verify({message, verificationKeys}))

  static generateKeys = userIDs => openpgp.generateKey({userIDs})

  static getURLHash = url => new Promise(
      (resolve, reject) => imageHash(url, 16, true, (error, data) => {
        if (error) {
          reject(error)
        } else {
          resolve(data)
        }
      })
    )

  static extract_sig_json = msg => msg.replace(/(\r\n|\n|\r)/gm, '')
      .replace('-----BEGIN PGP SIGNED MESSAGE-----Hash: SHA512', '')
      .replace('-----END PGP SIGNATURE-----', '')
      .split('-----BEGIN PGP SIGNATURE-----')

  static create_cert = (body, privateGranterKey, publicGranteeKey) =>
    Promise.all([
        body.image_url ? Nametag.getURLHash(body.image_url) : Promise.resolve('')
    ])
    .then((img_url_hash) => {
      const body_hashes = {...body, img_url_hash: img_url_hash[0]}
      return Nametag.sign(JSON.stringify(body_hashes), privateGranterKey)
    })
    .then(cert => Nametag.encrypt(cert, privateGranterKey, publicGranteeKey))

  static approve_cert = (cert_msg, privateGranteeKey, publicGranterKey) =>
    Nametag.decrypt(cert_msg, publicGranterKey, privateGranteeKey)
      .then(decrypted => {
        const [json, sig] = Nametag.extract_sig_json(decrypted.data)
        const body_w_sig = {...JSON.parse(json), granter_sig:sig}
        return Nametag.sign(JSON.stringify(body_w_sig), privateGranteeKey)
      })
      .then(approved_cert => Nametag.encrypt(approved_cert, privateGranteeKey, publicGranterKey))

  static finalize_cert = (approved_cert, privateGranterKey, publicGranteeKey, publicGranterKey) =>
    Nametag.decrypt(approved_cert, publicGranteeKey, privateGranterKey)
      .then(decrypted => {
        const [json, sig] = Nametag.extract_sig_json(decrypted.data)
        return {...JSON.parse(json), grantee_sig:sig, publicGranteeKey, publicGranterKey}
      })

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
