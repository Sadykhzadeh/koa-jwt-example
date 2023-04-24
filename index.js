const Koa = require('koa'); // Import the Koa web framework
const Router = require('koa-router'); // Import the Koa router
const bodyParser = require('koa-bodyparser'); // Import middleware for parsing HTTP request body
const jwt = require('jsonwebtoken'); // Import the JWT library

const app = new Koa(); // Create a new Koa app instance
const router = new Router(); // Create a new router instance

// In a real-world app, this would be a database of users
const users = [
  { username: 'azer', password: 'password1' },
  { username: 'huseyn', password: 'password2' }
];

const secretKey = 'my_secret_key'; // A secret key to use for JWT signing and verification

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
  const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
  ctx.body = { token };
});

app.use(bodyParser()); // Use the body parser middleware to parse HTTP request bodies
app.use(router.routes()); // Use the router to handle incoming requests

app.listen(3000, () => { // Start the server on port 3000
  console.log('Server running on port 3000');
});
