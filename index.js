const crypto = require('node:crypto'); // Node's own scrypt and timingSafeEqual
const Koa = require('koa'); // Import the Koa web framework
const Router = require('@koa/router'); // Import the Koa router
const bodyParser = require('koa-bodyparser'); // Import middleware for parsing HTTP request body
const jwt = require('jsonwebtoken'); // Import the JWT library
const cors = require('@koa/cors');

const app = new Koa(); // Create a new Koa app instance
const router = new Router(); // Create a new router instance

const port = Number.parseInt(process.env.PORT ?? '', 10) || 4000;
// Hardcoding the allowed origin means the sample only ever works for the one
// front end it was written against.
const allowedOrigin = process.env.CORS_ORIGIN || 'http://localhost:3000';

app.use(cors({ origin: allowedOrigin }));

// Unhandled errors reach Koa's default handler, which prints the stack and
// answers with whatever it decides. Answering here keeps the body predictable
// and keeps internals out of it - a malformed JSON body used to produce a
// stack trace in the log and an error page shaped by the body parser.
app.use(async (ctx, next) => {
  try {
    await next();
  } catch (error) {
    const clientError = error.status >= 400 && error.status < 500;
    ctx.status = clientError ? error.status : 500;
    // A rejected request is the client's problem and deserves one line; only
    // a fault on this side is worth a stack.
    if (clientError) console.warn(`${ctx.method} ${ctx.path} -> ${ctx.status}: ${error.message}`);
    else console.error(error);
    ctx.body = { error: clientError ? 'Bad request' : 'Internal server error' };
  }
});

// In a real-world app, this would be a database of users.
//
// The passwords are stored as `scrypt:<salt>:<hash>`, not as the passwords
// themselves. A sample is the first place somebody copies a pattern from, and
// a plain-text password column is the wrong pattern to hand them. scrypt is
// in Node's standard library, so this costs no dependency.
//
// To add a user:
//   node -e "const c=require('node:crypto');const s=c.randomBytes(16);\
//   console.log('scrypt:'+s.toString('hex')+':'+c.scryptSync('yourpassword',s,32).toString('hex'))"
const users = [
  { username: 'azer', password: 'scrypt:2725d9ac843f7081e5cb9c0f83c4339b:cf55e3c91e832f04ebbb1b80cafc61d1c4a5cde9d1fc17f0c1c2749329cb7936' },
  { username: 'huseyn', password: 'scrypt:8d0f76f28e6eb2d76a7037c9b4771958:d702601ca483da3a45f0147de9b95d9f87f8b4d4acf2d747c2b4edc0812628ee' }
];

const KEY_LENGTH = 32;

// A well-formed record whose password nobody knows, used to spend the same
// time on an unknown username as on a known one.
const NO_SUCH_USER = `scrypt:${crypto.randomBytes(16).toString('hex')}:${crypto.randomBytes(KEY_LENGTH).toString('hex')}`;

const scrypt = (password, salt) => new Promise((resolve, reject) => {
  crypto.scrypt(password, salt, KEY_LENGTH, (error, derived) => {
    // The synchronous scryptSync would block the event loop for every login
    // attempt, which is the whole server for the length of a hash.
    if (error) reject(error);
    else resolve(derived);
  });
});

const verifyPassword = async (stored, supplied) => {
  const [scheme, saltHex, hashHex] = String(stored).split(':');
  if (scheme !== 'scrypt' || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  if (expected.length !== KEY_LENGTH) return false;
  const actual = await scrypt(supplied, Buffer.from(saltHex, 'hex'));
  // A byte-by-byte === leaks, through how long it takes, how much of the hash
  // was right.
  return crypto.timingSafeEqual(expected, actual);
};

// The key to sign and verify with. Read from the environment, because a key
// written here is a key in everybody's copy of this file — and this file gets
// copied. The fallback is what keeps the sample runnable, and it is named so
// that nobody mistakes it for a value to keep.
const secretKey = process.env.JWT_SECRET || 'insecure-development-key';

if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  // The fallback exists so the sample runs, not so it ships.
  console.error('JWT_SECRET must be set when NODE_ENV=production');
  process.exit(1);
}

const BEARER = 'Bearer ';

// Middleware for verifying JWT tokens
const jwtMiddleware = async (ctx, next) => {
  const authHeader = ctx.request.headers.authorization;
  // `authHeader.replace('Bearer ', '')` left a header with no scheme at all
  // untouched, so `Authorization: <token>` was accepted exactly like
  // `Authorization: Bearer <token>`. The prefix is now required.
  if (!authHeader || !authHeader.startsWith(BEARER)) {
    ctx.status = 401;
    ctx.body = { error: 'No token provided' };
    return;
  }

  const token = authHeader.slice(BEARER.length).trim();
  try {
    // The algorithm is named rather than inferred: a verifier that accepts
    // whatever the token's own header asks for is the classic way a JWT check
    // gets talked out of checking anything.
    const decoded = jwt.verify(token, secretKey, { algorithms: ['HS256'] });
    ctx.state.user = decoded.username;
    await next();
  } catch (err) {
    ctx.status = 401;
    ctx.body = { error: 'Invalid token' };
  }
};

// Define a route for the root endpoint
router.get('/', (ctx) => { ctx.body = 'Hello World' })

// Define a route for the login endpoint
router.post('/login', async (ctx) => {
  const { username, password } = ctx.request.body ?? {};

  if (typeof username !== 'string' || typeof password !== 'string') {
    ctx.status = 400;
    ctx.body = { error: 'username and password are required' };
    return;
  }

  // Check if the username and password are valid
  const user = users.find(u => u.username === username);
  // A hash is computed even for an unknown username, against a record that
  // matches nothing, so that how long the answer takes does not tell an
  // attacker which accounts exist.
  const matches = await verifyPassword(user ? user.password : NO_SUCH_USER, password);
  const valid = Boolean(user) && matches;

  if (!valid) {
    ctx.status = 401;
    ctx.body = { error: 'Invalid credentials' };
    return;
  }

  // If the user is valid, create a JWT token and send it back
  const token = jwt.sign({ username }, secretKey, { algorithm: 'HS256', expiresIn: '1h' });
  ctx.body = { token };
});

// Define a route for a protected endpoint that requires a valid JWT token
router.get('/protected', jwtMiddleware, async (ctx) => {
  const user = ctx.state.user;
  ctx.body = { message: `Hello, ${user}!` };
});

app.use(bodyParser()); // Use the body parser middleware to parse HTTP request bodies
app.use(router.routes()); // Use the router to handle incoming requests
app.use(router.allowedMethods());

const server = app.listen(port, () => { // Start the server on the configured port
  console.log(`Server running on port ${port}`);
});

server.on('error', (error) => {
  // An occupied port used to end in an unhandled exception dump.
  if (error.code === 'EADDRINUSE') {
    console.error(`port ${port} is already in use`);
    process.exit(1);
  }
  throw error;
});
