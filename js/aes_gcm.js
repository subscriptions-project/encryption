/**
 * Subtle-based AES-GCM decryption supported on all browser types.
 */

/** 
 * Possibly wrap an object in a Promise.
 * @param {Object} op
 * @return {!Promise}
 */
function wrapCryptoOp(op) {
  if (typeof op.then == 'function') {
    return op;
  }
  return new Promise(function(resolve, reject) {
    op.oncomplete = function(e) {
      resolve(op.result);
    };
    op.onerror = function(e) {
      reject(e);
    };
  });
}

/**
 * Interpret a byte array as a UTF-8 string.
 * @param {!BufferSource} bytes
 * @return {string}
 */
function utf8Decode(bytes) {
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder('utf-8').decode(bytes);
  }
  const bytesBuffer = new Uint8Array(bytes.buffer || bytes);
  const array = new Array(bytesBuffer.length);
  for (let i = 0; i < bytesBuffer.length; i++) {
    array[i] = String.fromCharCode(bytesBuffer[i]);
  }
  const asciiString = array.join('');
  return decodeURIComponent(escape(asciiString));
}

/**
 * Converts a base64 string into a Uint8Array with the corresponding bytes.
 * @param {string} str
 * @return {!Uint8Array}
 */
function base64Decode(str) {
    const bytes = atob(str);
    const len = bytes.length;
    const array = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        const charCode = bytes.charCodeAt(i);
        if (charCode >= 256) {
            throw new Error("Decoded bytes not in range [0, 255].");
        }
        array[i] = charCode;
    }
    return array;
}

/**
 * Decrypts the input text using AES-GCM with the input key.
 * @param {string} key
 * @param {string} text
 * @return {!Promise}
 */
export function decryptAesGcm(key, text) {
  const keybytes = base64Decode(key);
  const isIE = !!window.msCrypto;
  const subtle = (window.crypto || window.msCrypto).subtle;
  return wrapCryptoOp(subtle.importKey('raw', keybytes.buffer,
                                       'AES-GCM',
                                       true, ['decrypt'])).
    then(function(formattedkey) {
      text = text.replace(/\s+/g, '');
      const contbuff = base64Decode(text).buffer;
      const iv = contbuff.slice(0, 12);
      const bytesToDecrypt = contbuff.slice(12);
      return wrapCryptoOp(subtle
        .decrypt(
          {
            name: 'AES-GCM',
            iv: iv,
            // IE requires "tag" of length 16.
            tag: isIE ? bytesToDecrypt.slice(bytesToDecrypt.byteLength - 16) : undefined,
            // Edge requires "tagLength".
            tagLength: 128 // block size (16): 1-128
          },
          formattedkey,
          // IE requires "tag" to be removed from the bytes.
          isIE ? bytesToDecrypt.slice(0, bytesToDecrypt.byteLength - 16) : bytesToDecrypt
      ))
      .then(function(buffer) {
        // 5. Decryption gives us raw bytes and we need to turn them into text.
        const decryptedBytes = new Uint8Array(buffer);
        return utf8Decode(decryptedBytes);
      }, function(error) {
        throw error;
      });
    });
}