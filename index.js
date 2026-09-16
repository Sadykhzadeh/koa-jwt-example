const Koa = require('koa'); // Import the Koa web framework
const Router = require('koa-router'); // Import the Koa router
const bodyParser = require('koa-bodyparser'); // Import middleware for parsing HTTP request body
const jwt = require('jsonwebtoken'); // Import the JWT library
const cors = require('@koa/cors');

const app = new Koa(); // Create a new Koa app instance
const router = new Router(); // Create a new router instance

// cors
app.use(cors({origin: 'http://localhost:3000'}));

// In a real-world app, this would be a database of users
const users = [
  { username: 'azer', password: 'password1' },
  { username: 'huseyn', password: 'password2' }
];

// The key to sign and verify with. Read from the environment, because a key
// written here is a key in everybody's copy of this file — and this file gets
// copied. The fallback is what keeps the sample runnable, and it is named so
// that nobody mistakes it for a value to keep.
const secretKey = process.env.JWT_SECRET || 'insecure-development-key';

// Middleware for verifying JWT tokens
const jwtMiddleware = async (ctx, next) => {
  const authHeader = ctx.request.headers.authorization;
  if (!authHeader) {
    ctx.status = 401;
    ctx.body = { error: 'No token provided' };
    return;
  }

  const token = authHeader.replace('Bearer ', '');
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
  const { username, password } = ctx.request.body;

  // Check if the username and password are valid
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
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

app.listen(4000, () => { // Start the server on port 4000
  console.log('Server running on port 4000');
});
