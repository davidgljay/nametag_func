const Nametag = require('../nametag')
const openpgp = require('openpgp')

describe('Generating a certificate', () => {

  const body = {
    desc: "A headline of < 150 chars", //This is a headline for the certificate
    text: "A detailed description of what this means and how it was verified.", //A longer description of what this certificate is and how it was verified.
    img_url: "https://relationalitylab.org/img/dj-headshot.png", //Optionally, an image URL to be associated with this certificate.
    data_url: "https://relationalitylab.org", //Like the image, this will be hashed for verification purposes.
    verified_by: ['cert1', 'cert2'],
    updates: ['cert3', 'cert4']
  }
  let granteeKeys
  let granterKeys
  let encryptedRequest

  beforeEach(() => {
    return Promise.all([
      openpgp.generateKey({userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }]}),
      openpgp.generateKey({userIDs: [{ name: 'Nametag', email: 'test@ntag.id' }]})
    ])
    .then(generatedKeys => {
        granteeKeys = generatedKeys[0]
        granterKeys = generatedKeys[1]
        return Promise.all([
          openpgp.createMessage({text: JSON.stringify(body)}),
          openpgp.readKey({ armoredKey: granterKeys.publicKey }),
          openpgp.readKey({ armoredKey: granterKeys.privateKey })
        ])
      })
    .then(([message, encryptionKeys, signingKeys]) => openpgp.encrypt({
            message,
            encryptionKeys,
            signingKeys
      }))
    .then(encrypted => {
      encryptedRequest = encrypted
     })
  })

  test('should decrypt and validate a message', () => {
    expect(encryptedRequest).toBeDefined()
    return Nametag.decrypt(encryptedRequest, granterKeys.publicKey, granterKeys.privateKey)
      .then(({data, signatures}) => {
        expect(data).toBe(JSON.stringify(body))
        expect(signatures).toBeDefined()
      })
  })

  test('should raise an error if not signed correctly', () => {
    //return expect(Nametag.decryptAndVerify(encryptedRequest, granteeKeys.publicKey, granterKeys.privateKey))
  })

  test('should raise an error if it fails to decrypt', () => {
    //return expect(Nametag.decryptAndVerify(encryptedRequest, granterKeys.publicKey, granteeKeys.privateKey))
  })

  test('should generate a keypair', () => {
      return  Nametag.generateKeys([{ name: 'Jon Smith', email: 'jon@example.com' }])
        .then(keys => {
          expect(keys.privateKey).toBeDefined()
          expect(keys.publicKey).toBeDefined()
          expect(keys.revocationCertificate).toBeDefined()
        })
  })

  test('should generate a hash of the image in a suggested URL', () => {
    const url = 'https://relationalitylab.org/img/dj-headshot.png'
    return Nametag.getURLHash(url)
      .then(hash => expect(hash).toBe('fc3ff00fe007c007c011cfd11fe01ff009700df08ff187f180e1c1e3e0c7f81f'))
  })

  test('it should encrypt a message for the grantee', () => {

    return Nametag.encrypt(JSON.stringify(body), granterKeys.privateKey, granteeKeys.publicKey)
      .then(encrypted => {
        expect(encrypted).toContain('-----BEGIN PGP MESSAGE-----')
      })
  })

  test('it should sign a message', () => {
    return Nametag.sign(JSON.stringify(body), granteeKeys.privateKey)
      .then(signed => {
        expect(signed).toContain('-----BEGIN PGP SIGNED MESSAGE-----')
      })
  })

  test('it should verify a message', () => {

    return Promise.all([
          openpgp.createCleartextMessage({text: JSON.stringify(body)}),
          openpgp.readPrivateKey({ armoredKey: granteeKeys.privateKey})
        ])
      .then(([message, signingKeys]) => openpgp.sign({message, signingKeys}))
      .then(signed => Nametag.verify(signed, granteeKeys.publicKey))
      .then(result => {
        expect(result.signatures[0]).toBeDefined()
      })
  })

  test('it should generate a ceritificate', () => {
    return Nametag.create_cert(body, granterKeys.privateKey, granteeKeys.publicKey)
      .then(cert => {
        expect(cert).toContain('-----BEGIN PGP MESSAGE-----')
        return Promise.all([
          openpgp.readMessage({armoredMessage: cert}),
          openpgp.readKey({ armoredKey: granterKeys.publicKey}),
          openpgp.readPrivateKey({ armoredKey: granteeKeys.privateKey})
        ])
      })
      .then(([message, verificationKeys, decryptionKeys]) => openpgp.decrypt({
            message,
            decryptionKeys,
            expectSigned: true,
            verificationKeys // mandatory with expectSigned=true
          })
        )
        .then(decrypted => Promise.all([
              openpgp.readCleartextMessage({cleartextMessage: decrypted.data}),
              openpgp.readKey({ armoredKey: granteeKeys.publicKey})
            ])
        .then(([message, verificationKeys]) => openpgp.verify({message, verificationKeys})))
        .then(verified => {
          const cert = JSON.parse(verified.data)
          expect(cert.desc).toBe(body.desc)
          expect(cert.img_url_hash).toBeDefined()
        })
  })

  test('it should approve a certificate', () => {
    return Nametag.create_cert(body, granterKeys.privateKey, granteeKeys.publicKey)
      .then(cert_msg => Nametag.approve_cert(cert_msg, granteeKeys.privateKey, granterKeys.publicKey))
      .then(approved_cert => {
        expect(approved_cert).toContain('-----BEGIN PGP MESSAGE-----')
        return Promise.all([
          openpgp.readMessage({armoredMessage: approved_cert}),
          openpgp.readKey({ armoredKey: granteeKeys.publicKey}),
          openpgp.readPrivateKey({ armoredKey: granterKeys.privateKey})
        ])
      })
      .then(([message, verificationKeys, decryptionKeys]) => openpgp.decrypt({
            message,
            decryptionKeys,
            expectSigned: true,
            verificationKeys // mandatory with expectSigned=true
          })
        )
        .then(decrypted => Promise.all([
              openpgp.readCleartextMessage({cleartextMessage: decrypted.data}),
              openpgp.readKey({ armoredKey: granterKeys.publicKey})
            ])
        .then(([message, verificationKeys]) => openpgp.verify({message, verificationKeys})))
        .then(verified => {
          const approved_cert = JSON.parse(verified.data)
          expect(approved_cert.desc).toBe(body.desc)
          expect(approved_cert.granter_sig).toBeDefined()
        })
  })

  test('it should finalize a certificate', () => {
    return Nametag.create_cert(body, granterKeys.privateKey, granteeKeys.publicKey)
      .then(cert_msg => Nametag.approve_cert(cert_msg, granteeKeys.privateKey, granterKeys.publicKey))
      .then(approved_cert => Nametag.finalize_cert(approved_cert, granterKeys.privateKey, granteeKeys.publicKey, granterKeys.publicKey))
      .then(finalized_cert => {
        expect(finalized_cert.desc).toBe(body.desc)
        expect(finalized_cert.text).toBe(body.text)
        expect(finalized_cert.publicGranteeKey).toBeDefined()
        expect(finalized_cert.publicGranterKey).toBeDefined()
      })
  })

  test('it should verify a certificate', () => {

  })

})
