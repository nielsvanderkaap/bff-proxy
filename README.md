# Azure API management & OAuth 2.0 for Browser-Based Apps

## Single Page Applications

Single Page Applications (SPA) rely on a single webpage that is dynamically rewritten by client side scripting.
They deliver a more native experience by providing faster transitions without loading new pages.
Typically, SPAs interact with the backend data model using REST APIs. 
These interactions often require the browser to keep track of OAuth 2.0 Access Tokens for authorizing requests.

This results in several challenges:
- The frontend must implement all interactions with authorization server(s).
- APIs require public OAuth clients, enabling client impersonation.
- OAuth 2.0 access tokens are stored insecurely in the browser application, which introduces security risks.
- APIs may become vulnerable to client-side attacks like Protocol Downgrade, Cross Site Scripting (XSS) and Cross Site Request Forgery (CSRF).

The above issues can be resolved by implementing a [Backend For Frontend (BFF) proxy](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#name-single-domain-browser-based) or [Token Handler Pattern](https://curity.io/resources/learn/the-token-handler-pattern/).

## Security
Single Page Applications require some thought about security details.

### Cross-Site Scripting
Cross-site scripting (XSS) attacks rely on the injection of malicious client-side code.
The application executes this code, which allows an attacker to:

- Perform HTTP requests to trusted domains, to obtain secured data or to perform a malicious operation.
- Read local-storage, indexedDb and cookies, to obtain session tokens and secure data.
- Perform HTTP requests to untrusted domains, to store stolen data.

An attacker can thus abuse an authentic session between the browser and the APIs, and perform any operation for the duration of the browser session.
Furthermore, if an injected script manages to capture session tokens, access tokens or refresh tokens, they can be forwarded to the attacker.
The attacker can then even hijack the session and continue the abuse outside the original browser application.

Preventing XSS is mainly a responsibility of the developer.
However, [Content Security Policy (CSP)](https://content-security-policy.com/) headers provide a second line of defense against XSS.
They allow detailed specification of valid locations for scripts and content.
They can also prevent framing attacks and protocol downgrade attacks.

Using `HttpOnly` cookies to manage the session between browsers and APIs prevents client-side scripts from reading cookie contents.
Although the attacker can still perform API requests that include cookies, the session token itself is not accessible.
The attacker can thus not steal the session, and keep it alive after the browser session is closed.

### Cross-Site Request Forgery

Cross-Site Request Forgery (CSRF) attacks abuse authentic session between browsers and APIs that rely on cookies or other cached credentials.
The attacker performs API requests to an authentic API, from a malicious website. 
Since the browser caches the credentials or cookies for the domain of the API, the request succeeds.
The malicious site can forward this information to the attacker, or perform transactions using the authentic session.
There are multiple ways to prevent CSRF attacks.

First, the [same-origin policy](https://en.wikipedia.org/wiki/Same-origin_policy) disallows requests from a page from origin A to origin B with a different protocol, port, or host.
CORS loosens these restrictions by introducing a preflight `OPTIONS` request to origin B, before performing the actual request.
The response of the preflight request contains an `Access-Control-Allow-Origin` header that includes the allowed origins.
If the header contains a wildcard `*` or origin A, the request is allowed.
Otherwise, the request is blocked.
This mechanism prevents that malicious websites can abuse an authentic API.
The BFF proxy required CORS policies when the SPA is hosted at a different domain.
If a backend does not implement CORS policies itself, API Management can implement these details.
Azure API management provides the CORS [policy](https://learn.microsoft.com/en-us/azure/API-management/CORS-policy) to process the pre-request.

Alternatively, APIs can use [CSRF tokens](https://brightsec.com/blog/CSRF-token/) to prevent CSRF attacks.
After session initialization, the API generates a random CSRF token and stores this in the session (for instance using a `HttpOnly` cookie).
The CSRF token is also returned to the application, and stored in a location that can only be accessed by the application.
The application includes the CSRF token in each subsequent request to the API, where it is checked against the value in the session.
The API blocks a request when the CSRF token from the session does not match the value that was padded in the request.
This protects the API against CRSF attacks, since the malicious website cannot retrieve the CSRF token from the authentic application.

## Backend For Frontend proxy using HttpOnly cookies

Instead of directly connecting to the data model backend, all requests to backend APIs run through the BFF proxy.
Here, the connection between the browser and the BFF proxy relies on a session cookie.
This session cookie contains the `HttpOnly`, `MaxAge` and `Secure` attributes, to make sure that scripts cannot extract the session token, prevent protocol downgrade attacks, and provide a session timeout mechanism.

The BFF pattern can be implemented stateless or stateful.
The stateless variant encrypts all relevant oauth information (access tokens, refresh tokens, code verifiers) and stores it in the [session token](https://learn.microsoft.com/en-us/azure/API-management/howto-protect-backend-frontend-azure-ad-b2c).
This approach limits storage requirements on the BFF proxy.
However, it increases request and response sizes, and requires a policy for encryption key rotation.
The stateful variant caches all relevant oauth information in the proxy, and uses a smaller randomized session token.

Azure API Management is a suitable platform for implementing a BFF:
- It supports policies to implement Access Token and session cookie management.
- It supports internal caching of access token and refresh token.
- It allows additional logic to be added to API calls, for instance for implementing [CSRF tokens](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- It is a scalable service that allows for high throughput.

This post implements a stateful variant of the BFF pattern in Azure API Management, where it uses Azure Active Directory for authorizing requests to backend APIs.

## Hosting the SPA
The SPA consists of a html page that uses Javascript to dynamically load content from different domains.
This may results in some challenges:
- CSP headers must be properly initialized for all domains where content is loaded from.
- Modern browsers do not support third party cookies for managing browser sessions for APIs.
- The CORS policies may have to be configured to allow requests from the SPA.

Exposing this page through an API Management solution provides the following advantages:
- The SPA can use First Party cookies to manage the session with APIs.
- API Management policies can implement Content Security Policy (CSP) by generating and setting a nonce in the script body and in the `Content-Security-Policy` HTTP header. 
  This acts as a second line of defense for Cross-Site Scripting (XSS) attacks.
- No CORS policies or CSRF headers need to be configured, since all requests run through one origin.

---
**_NOTE_** 
Solutions like Azure Static Sites introduce [backend APIs](https://learn.microsoft.com/en-us/azure/static-web-apps/add-API?tabs=vanilla-javascript), to host APIs within the same domain as the website itself. 
This resolves the issues with CORS and third party cookies, but it does not provide a mechanism to dynamically add nonces for CSP headers.
The alternative is to use fixed CSP headers containing the absolute content location.
Another alternative is to host the BFF proxy at a subdomain of the website, since cookies can be shared.

---

## Implementing a Stateful BFF-proxy using Azure Api Management

The BFF proxy is a confidential OAuth 2.0 client that is responsible for managing all access tokens.
For each inbound request, it translates the session cookie the right OAuth 2.0 access token.
For this, API Management requires a confidential `client-id` and client credentials.
The request flow is shown in the figure below:
![Request flow for HttpOnly cookie managed sessions](./doc/cookies.drawio.png)

First, API Management exposes an `/authorize` endpoint for retrieving authorization codes from Azure Active Directory.
This endpoint requires the following [oauth parameters](https://www.oauth.com/oauth2-servers/authorization/the-authorization-request/):
- scope 
- response_type
- nonce 
- state 

The `scope`, `nonce` and `response_type` parameters can also be generated by the BFF proxy.

API Management forwards the browser to the Azure Active Directory authorization endpoint using HTTP response code `303 See Other`. 
Furthermore, it generates a random session token and places it in the `Session-Token` cookie.
Finally, it adds the `client_id`, `code_challenge_method` (PKCE), `code_challenge` (PKCE) and `response_mode` OAuth parameters to the redirect uri.
Here, the scope can either be cached by the proxy, or is encoded in the `state` parameter together with the inbound `state` parameter.
The `code_verifier` that corresponds to the `code_challenge` is cached by the BFF proxy, to prevent browsers from retrieving tokens.
The user must now finish the login process for Azure Active Directory in the browser. 

---
**_NOTE_** 
Response mode is `query` by default, but `form_post` is also supported to immediately retrieve de OpenId token.
However, this approach requires a HTTP `POST` redirect instead of a `GET`.
The `fragment` mode is not supported, since it cannot be interpreted by API Management.

---

After a successful login, the authorization server redirects the browser to the BFF proxy in Api Management.
Based on cookie (session token) and state, the BFF proxy retrieves scopes, nonce and code verifier (PKCE).
API Management retrieves the authorization code, and requests the corresponding `access_token` and `refresh_token`.
API Managements caches the tokens and redirects the browser back to the SPA, the cache duration matches the token lifetimes.
Tokens use separate key-value pairs in the cache store.
Here, access tokens use the key `AT-{Session-Token}-{scope(s)}`, while refresh tokens use `RT-{Session-Token}-{scope(s)}`.
This reduced complexity because the cache store manages token retention.

---
**_NOTE_** 
The caching keys contain a combination of the `Session-Token`, the `scope(s)`, and the type of token.
This allows applications to use multiple fine-grained access tokens, instead of one master token.
This reduces token abuse in backend systems when the BFF proxy exposes multiple backend systems.

---

With the relation between cookie (session token) and access token established in the BFF proxy, the browser may perform a request to the backend API through API Management.
The browser must add the `scope` parameters to this request, to determine the target access token to use.
The BFF proxy uses a [policy fragment](https://learn.microsoft.com/en-us/azure/API-management/policy-fragments) that implements the following decision tree to obtain tokens:
1. If an access token is present in the cache with the same `Session-Token` and `scope`, return it.
2. If a refresh token is present in the cache with the same `Session-Token` and `scope`, request a new access token and return it.
3. return an `Unauthorized` exception.

The SPA may force token refresh by calling the `/refresh` endpoint on the BFF proxy, where the `scope` must be added to target a certain access token.

## Conclusion

A BFF proxy helps to simplify and secure the implementation of a SPA.
The most challenging aspect of building a BFF is session management.
This entails a browser contained secret that is passed to the BFF proxy during each request, but is not accessible by client side scripts.
Using `HttpOnly` cookies are a great solution to solve is problem, but APIs must be hosted at the same domain or subdomain as the static content of the application.
Also, CSRF tokens or tight CORS policies must be used to prevent CSRF attacks, since a `HttpOnly` cookie is also send for requests from different origins.

Another aspect of BFF proxies is scoping: what to do when multiple frontend applications require a BFF proxy.
Different frontend applications with similar API requirements may share a BFF proxy.
When considering Azure API Management, however, provisioning an extra BFF proxy for each frontend application can be done with little effort.
Furthermore, this results in better separation of frontend applications, and simplifies maintainability.

Finally, OAuth scopes for backend systems require some attention:
- Frontend applications may require API requests to multiple backend systems, introducing risks of token abuse by backend systems.
- Frontend applications may have different user roles, requiring dynamic scopes for the same backend system.
The current implementation solves these issues by exposing the backend scopes to the frontend.
Each request requires a query parameter that indicates the right scope.
The BFF proxy then retrieves the access token from the cache, using a key that consists of the session token and the scope.
This mechanism provides maximum flexibility, still follows OAuth conventions, and results in minimal configuration effort in the BFF.
Alternatively, the BFF proxy may map the frontend role to the required backend scopes. 
This approach hides implementation details and reduces complexity at the frontend application, but increases complexity opf the BFF proxy.