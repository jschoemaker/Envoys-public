// Must run before any app imports so db.ts initialises with an in-memory database.
process.env.DB_PATH = ':memory:'
process.env.SERVICE_DOMAIN = 'envoys.me'
process.env.BASE_URL = 'http://localhost:3000'
// RFC 8032 §7.1 Test 1 public key (non-secret) — exercises the /.well-known/did.json route.
process.env.ENVOYS_SERVICE_DID_PUBLIC_JWK_X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
