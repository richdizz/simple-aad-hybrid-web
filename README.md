# SIMPLE-AAD-HYBRID-WEB

Microsoft has long pushed implicit flow securing single-page apps (SPAs). However, implicit flow doesn't provide the idea user experience given that OAuth flow does not provide refresh tokens for longer-term access. Proof Key for Code Exchange (PKCE) is an emerging solution to this, but Azure AD doesn't yet support PKCE (login.microsoft.com doesn't support CORS). In reality, I think most serious SPAs still have a server-side component. Thus, why wouldn't you do a traditional authorization code OAuth flow on the server (which includes refresh tokens). The sample in this repo outlines a pattern for doing this "hybrid" web application...that is single page app in the client with server-side auth flows and secure APIs.

## The patterns

As far as I can tell, there are two primary patterns for a hybrid web app:

1) Send access tokens to the client so it can make it's own API calls to secure 3rd party APIs (ex: Microsoft Graph)
2) Proxy all secure 3rd party APIs calls through the server (read: the client calls it's own backend and that backend makes the call to a secure API like the Microsoft Graph)

My sample uses the second approach. I go further to secure the backend API by Azure AD, which the client can call via id_token.

## Caveats 

This sample uses a few hacks to simplify the pattern for easier understanding:

- The sample doesn't use a real token cache...it simply uses a global array property that stores tokens in-memory on the server. This is obviously a significant hack that shouldn't be followed in production
- I'm sending the actual id_token to the client where it is stored in the normal cookie. In reality, the id_token and client storage should follow security best practices.


# Running the app

To run the application, clone the repo, run `npm install` and then `node app.js`