/** Reviewed public endpoints. Never resolve token-selected jku/x5u URLs. */
export const publicOidcSources = {
  miargentina: {
    issuer: "https://id.argentina.gob.ar",
    jwks: "https://id.argentina.gob.ar/jwks",
  },
  google: {
    issuer: "https://accounts.google.com",
    jwks: "https://www.googleapis.com/oauth2/v3/certs",
  },
  apple: {
    issuer: "https://appleid.apple.com",
    jwks: "https://appleid.apple.com/auth/keys",
  },
  telegram: {
    issuer: "https://oauth.telegram.org",
    jwks: "https://oauth.telegram.org/.well-known/jwks.json",
  },
  kakao: {
    issuer: "https://kauth.kakao.com",
    jwks: "https://kauth.kakao.com/.well-known/jwks.json",
  },
  facebook: {
    issuer: "https://www.facebook.com",
    jwks: "https://www.facebook.com/.well-known/oauth/openid/jwks/",
  },
  linkedin: {
    issuer: "https://www.linkedin.com",
    jwks: "https://www.linkedin.com/oauth/openid/jwks",
  },
  govbr: {
    issuer: "https://sso.acesso.gov.br/",
    jwks: "https://sso.acesso.gov.br/jwk",
  },
  govbr_staging: {
    issuer: "https://sso.staging.acesso.gov.br/",
    jwks: "https://sso.staging.acesso.gov.br/jwk",
  },
  line: {
    issuer: "https://access.line.me",
    jwks: "https://api.line.me/oauth2/v2.1/certs",
  },
  entra: {
    issuer: "https://login.microsoftonline.com/{tenantid}/v2.0",
    jwks: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
  },
  franceconnect_v2: {
    issuer: "https://oidc.franceconnect.gouv.fr/api/v2",
    jwks: "https://oidc.franceconnect.gouv.fr/api/v2/jwks",
  },
  franceconnect_v2_sandbox: {
    issuer: "https://fcp-low.sbx.dev-franceconnect.fr/api/v2",
    jwks: "https://fcp-low.sbx.dev-franceconnect.fr/api/v2/jwks",
  },
  franceconnect: {
    issuer: "https://auth.franceconnect.gouv.fr/api/v2",
    jwks: "https://auth.franceconnect.gouv.fr/api/v2/jwks",
  },
  franceconnect_integration: {
    issuer: "https://auth.integ01.dev-franceconnect.fr/api/v2",
    jwks: "https://auth.integ01.dev-franceconnect.fr/api/v2/jwks",
  },
} as const;
