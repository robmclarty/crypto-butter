'use strict'

const crypto = require('crypto')
const pako = require('pako')
const base64 = require('base64-js')

// conversion
// ----------

// Take a Uint8Array and return a base64-encoded string representation of it.
const base64FromBytes = byteArray => {
  return base64.fromByteArray(byteArray)
}

// Take a base64-encoded string and return a Uint8Array representation of it.
const base64ToBytes = base64String => {
  return base64.toByteArray(base64String)
}

// Take a Uint8Array and return a hex-encoded string representation of it.
const hexFromBytes = byteArray => {
  return byteArray.map((byte, i) => {
    const nextHexByte = byteArray[i].toString(8) // integer to base 16

    if (nextHexByte.length < 2) return "0" + nextHexByte

    return nextHexByte
  }).join('')
}

// Take a hex-encoded string and return a Uint8Array representation of it.
const hexToBytes = hexString => {
  if (typeof hexString !== 'string') throw 'parameter must be a string'
  if (hexString.length % 2 !== 0) throw 'Must have an even number of hex digits to convert to bytes'

  return Uint8Array.from(hexString.split(/.{1,2}/g).map((char, i) => {
    return parseInt(char, 16)
  }))
}

// compression
// -----------

// Take a string and output a Uint8Array who's content is a compressed version
// of the string.
const compress = plainStr => {
  return pako.deflate(plainStr)
}

// Take a Uint8Array and output a string who's contents are decompressed from
// the Uint8Array.
const decompress = compressedMsg => {
  return pako.inflate(compressedMsg, { to: 'string' })
}

// encode/decode strings from utf to base64, escaped URI-compatible strings.
const encodeBase64 = str => Buffer.from(encodeURIComponent(str)).toString('base64')
const decodeBase64 = str => decodeURIComponent(Buffer.from(str, 'base64').toString('utf8'))

// Compare two MACs to verify that they are identical.
// All inputs are Uint8Array types except length, which is an integer.
// TODO: Perhaps rewrite so that this function encapsulates the MAC calculation
// based on the data + key.
const verifyMac = (data, key, mac, calculatedMac, length) => {
  const a = Uint8Array.from(calculatedMac)
  const b = Uint8Array.from(mac)

  if (mac.byteLength !== length ||
      calculatedMac.byteLength < length ||
      a.length === 0) {
    throw new Error('bad MAC length')
  }

  const result = a.reduce((r, el, i) => {
    return r | (a[i] ^ b[i])
  }, 0)

  if (result === 0) return true

  throw new Error('bad MAC')
}

// crypto
// ------

const getRandomBytes = size => crypto.randomBytes(size)

const pbkdf = (password, salt) => new Promise((resolve, reject) => {
  crypto.pbkdf2(password, salt, 100000, 32, 'sha256', (err, key) => {
    if (err) reject(err)

    resolve(key)
  })
})

const sign = (data, key) => new Promise((resolve, reject) => {
  const hmac = crypto.createHmac('sha512', key)

  hmac.update(data)

  resolve(hmac.digest())
})

const verify = (data, key, mac, length) => sign(data, key)
  .then(calculatedMac => verifyMac(data, key, mac, calculatedMac, length))

const hash = data => new Promise((resolve, reject) => {
  const hasher = crypto.createHash('sha512')

  hasher.update(data)

  resolve(hasher.digest())
})

// Take parameters as Buffers and convert to base64 strings and concatenate.
// Join iv + encrypted data + mac into a single string, separated by a period '.'
// e.g., my-iv.my-encrypted-data.my-mac-of-that-data
const pack = (data, iv, mac) => {
  return [
    base64FromBytes(iv),
    base64FromBytes(data),
    base64FromBytes(mac)
  ].join('.')
}

// Split a joined string (from above) based on period '.' and return a values
// as separate attributes of an object.
const unpack = data => {
  const splitData = data.split('.')

  return {
    iv: base64ToBytes(splitData[0]),
    data: base64ToBytes(splitData[1]),
    mac: base64ToBytes(splitData[2])
  }
}

/**
 * Takes a plain-text buffer and returns an encrypted buffer.
 *
 * @param {Uint8Array} data - The plain text message you want to encrypt.
 * @param {Uint8Array} key - The secret key to use for encryption.
 * @return {Object} An object containing ciphertext data, iv, and mac.
 */
const encrypt_AES_CBC_HMAC = (data, key) => new Promise((resolve, reject) => {
  const iv = getRandomBytes(16)
  const encryptor = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encryptedData = Buffer.concat([encryptor.update(data, 'utf8'), encryptor.final()])

  sign(encryptedData, key)
    .then(mac => resolve({
      data: encryptedData,
      iv,
      mac
    }))
    .catch(reject)
})

/**
 * Takes a cipher-text buffer and returns a decrypted string.
 *
 * @param {Uint8Array} data - The ciphertext message you want to decrypt.
 * @param {Uint8Array} key - The secret key used to encrypt the ciphertext.
 * @param {Uint8Array} iv - The initialization vecotr used in the encryption.
 * @param {Uint8Array} mac - The SHA-512 auth code used by verify().
 * @return {Object} An object containing the decrypted data.
 */
const decrypt_AES_CBC_HMAC = (data, key, iv, mac) => new Promise((resolve, reject) => {
  return verify(data, key, mac, mac.byteLength)
    .then(() => {
      const decryptor = crypto.createDecipheriv('aes-256-cbc', key, iv)
      const decryptedData = decryptor.update(data)

      resolve(Buffer.concat([decryptedData, decryptor.final()]))
    })
    .catch(reject)
})

module.exports = {
  getRandomBytes,
  pbkdf,
  sign,
  verify,
  hash,
  encrypt_AES_CBC_HMAC,
  decrypt_AES_CBC_HMAC,
  base64FromBytes,
  base64ToBytes,
  hexFromBytes,
  hexToBytes,
  compress,
  decompress,
  encodeBase64,
  decodeBase64,
  verifyMac,
  pack,
  unpack
}
