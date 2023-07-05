import { openDB } from 'idb';

const dbPromise = openDB('key-store', 1, {
    upgrade(db) {
        db.createObjectStore('keys');
    },
});

function base64ToUint8Array(base64Contents) {
    base64Contents = base64Contents.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    const content = atob(base64Contents);
    return new Uint8Array(content.split('').map((c) => c.charCodeAt(0)));
}

function stringToUint8Array(contents) {
    const encoded = btoa(unescape(encodeURIComponent(contents)));
    return base64ToUint8Array(encoded);
}

function uint8ArrayToString(unsignedArray) {
    const base64string = btoa(String.fromCharCode(...unsignedArray));
    return base64string.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function arrayBufferToBase64(arrayBuffer) {
    const byteArray = new Uint8Array(arrayBuffer);
    let byteString = '';
    byteArray.forEach((byte) => {
        byteString += String.fromCharCode(byte);
    });
    return btoa(byteString);
}

function breakPemIntoMultipleLines(pem) {
    const charsPerLine = 64;
    let pemContents = '';
    while (pem.length > 0) {
        pemContents += `${pem.substring(0, charsPerLine)}\n`;
        pem = pem.substring(64);
    }
    return pemContents;
}

// Function for getting the key from IndexedDb
async function getKey() {
    let key = await (await dbPromise).get('keys', 1);

    if (key == undefined) {

        console.log("Create new key")
        key = await window.crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            false,
            ['sign']
        ).then(function (key) {
            return key;
        })
        await setKey(key);
    }

    return key
}

// Function for storing the key in IndexedDb
async function setKey(key) {
    return (await dbPromise).put('keys', key, 1);
}

function str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

export async function GenerateJwt() {

    // Retrieve key from indexedDb, or generate a new key
    let key = await getKey()


    var header = {
        "alg": "RS256",
        "typ": "JWT"
    }

    var claims = {
        "role": "admin",
    }


    const headerBase64 = uint8ArrayToString(stringToUint8Array(JSON.stringify(header)));
    const payloadBase64 = uint8ArrayToString(stringToUint8Array(JSON.stringify(claims)));
    const headerAndPayload = `${headerBase64}.${payloadBase64}`;
    const messageAsUint8Array = stringToUint8Array(headerAndPayload);

    var sigType = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
    }

    return await window.crypto.subtle.sign(
        sigType,
        key.privateKey,
        messageAsUint8Array
    ).then(signature => {
        return `${headerAndPayload}.${uint8ArrayToString(new Uint8Array(signature))}`
    });

}

export async function GetPublicKey() {
    let key = await getKey()

    return await window.crypto.subtle.exportKey("jwk", key.publicKey)
}