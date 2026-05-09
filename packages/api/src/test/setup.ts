// Must run before any app imports so db.ts initialises with an in-memory database.
process.env.DB_PATH = ':memory:'
process.env.SERVICE_DOMAIN = 'envoys.me'
process.env.BASE_URL = 'http://localhost:3000'
