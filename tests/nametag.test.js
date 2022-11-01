const Nametag = require('../nametag')
const openpgp = require('openpgp')

describe('Generating a certificate', () => {



  const body = {
    text: "Description of the certification.",
    image: "url of an image to be associated with this certification",
    verified_by: ['cert1', 'cert2']
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
    return Nametag.decryptAndVerify(encryptedRequest, granterKeys.publicKey, granterKeys.privateKey)
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

})


// 1. Receive this JSON
// 2. Remove the sig, verify it with the sig key. Else return 400.
// 3. Generate a keypair.
// 4. Generate a hash of the image at the established URL.
// 5. Sign the text and image with the granter side of the keypair (this is used to send verified messages as the granter.)
// 6. Sign the text and image as every one of the verified keys.
// 7. Add the image_hash, granter sig and key, and the verified URLs and sigs to the object.
// 8. Convert the object to JSON
// 9. Encrypt w/ the grantee key
// 10. Return encrypted text and public granter key
