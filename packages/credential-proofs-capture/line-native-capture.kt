// Add to an existing, correctly configured LINE SDK Android app.
// Requires the app's LINE Login channel and openid permission. No channel
// secret belongs in a client app. Obtain this nonce from the Aztec caller.
val actionNonce = "<64 lowercase hex characters from the account action>"
val loginParams = LineAuthenticationParams.Builder()
    .scopes(listOf(Scope.OPENID))
    .nonce(actionNonce)
    .build()
// Pass loginParams to the SDK login-intent API used by your app. In its result
// callback, retain the returned raw encoded ID token privately;
// verify issuer/channel/subject/nonce/time with `credential-proofs-inputs line import`.
// This snippet does not initiate login or send a credential anywhere.
