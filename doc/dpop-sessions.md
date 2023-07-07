# Backend For Frontend proxy using Demonstrating Proof of Possession tokens
---
**_NOTE_** 
Managing sessions via DPoP requires key-pairs with private keys that cannot be touched by client-side scripts.
Non-extractable Browser generated Cryptokeys are not usable, since XSS attacks may override them with imported keys and restart the authorization flow.
This is not the case when server-generated keys are used. 
However, this requires a trusted client-script at the redirect endpoint that imports the key-pair into a non-extractable Cryptokey.
Not sure whether this is safe.

---

A downside of cookie based sessions is the requirement for first-party cookies. 
This requires the BFF proxy to be hosted at the same domain as the SPA.
A solution for this approach is to use Demonstrated Proof of Possession (DPoP) tokens.
The corresponding flow is shown below:
![Request flow for DPoP managed sessions](./doc/dpop.drawio.png)

The DPoP approach replaces the `Session-Token` with the public key of a server-generated key-pair.
This BFF proxy returns the key-pair through an URI fragment in the redirect URI.
The application imports the key-pair in a non-extractable [CryptoKeyPair](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKeyPair) object instance, clears the Uri fragment, and persists it in IndexedDB.
The object instance can be used to sign data, but the private key is inaccessible for client code.
Thus, XSS attacks can still perform malicious requests, but they cannot steal the browser session.

**_NOTE_** It is also possible to let the browser generate a key-pair, but this allows an XSS attacker to import a known key-pair. This would allow the attacker to steal the session.

After processing the redirect, the browser may perform a request to the backend API through API Management.
The browser must add the `scope` parameter and `DPop` header to this request.
The DPoP header contains a JWT that is signed by the key-pair in IndexedDB.
It contains the following claims:

- `jti`: Unique identifier for the request.
- `htm`: HTTP method of the request
- `htu`: target uri of the request
- `iat`: creation timestamp of the JWT

The BFF proxy performs the following checks:
- `htm` & `htu` match the request
- `iat` is within an acceptable range of time. 
- `jti` has not been used already. 

The `jti` claim is cached for the duration of at least the acceptable window of the `iat`.


## Conclusion
Key-pair driven sessions allow APIs to be hosted at different domains, since the session-state is transmitted using HTTP headers
Moreover, they are less prone to CSRF issues.
However, attackers may target the redirect mechanism that is triggered after authorization, to obtain the private key.
Alternatively, browser generated key-pairs are vulnerable to being replaced with malicious imported key-pairs from an XSS attacker.
This last option would result is full theft of the session.
Finally, it is hard to fully prevent reuse of DPoP JWT tokens, since BFF proxies are often implemented as a distributed system and cached values take a small time to become available.

