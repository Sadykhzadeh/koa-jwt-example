<p align="center">
  <h3 align="center">Koa-JWT-Example</h3>
  <p align="center">
    just a sample of how JWT works via Koa.JS web framework
    <br/>
    <br/>
  </p>
</p>



## Table Of Contents

* [Built With](#built-with)
* [Usage](#usage)
* [Contributing](#contributing)

## Built With

- jsonwebtoken (the JWT library)
- koa (Koa web framework)
- koa-bodyparser (Koa middleware for parsing HTTP request body)
- @koa/router (the Koa router; `koa-router` itself is unmaintained)
- @koa/cors
- `node:crypto` for password hashing, so that costs no dependency

## Usage

```sh
npm ci
cp .env.example .env     # optional
npm start
npm test                 # walks the auth flow, including the refusals
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `JWT_SECRET` | `insecure-development-key` | Signing key. **Required** when `NODE_ENV=production`, where the server refuses to start without it. |
| `PORT` | `4000` | Port to listen on. |
| `CORS_ORIGIN` | `http://localhost:3000` | Origin allowed by CORS. |

### Try it

```sh
TOKEN=$(curl -s -H 'Content-Type: application/json'   -d '{"username":"azer","password":"password1"}'   localhost:4000/login | sed -E 's/.*"token":"([^"]+)".*//')

curl -s -H "Authorization: Bearer $TOKEN" localhost:4000/protected
```

## What this sample tries to get right

A sample is the first place somebody copies a pattern from, so the patterns
here are meant to be the ones worth copying:

- **Passwords are stored as scrypt hashes**, as `scrypt:<salt>:<hash>`, never
  as the passwords. `node:crypto` provides scrypt, so this needs no
  dependency. The asynchronous form is used: `scryptSync` would block the
  event loop - the whole server - for the length of every hash.
- **The comparison is `timingSafeEqual`.** A byte-by-byte `===` leaks, through
  how long it takes, how much of the hash was right.
- **An unknown username costs the same as a known one.** A hash is computed
  either way, so response time does not reveal which accounts exist.
- **The verifying algorithm is named**, not taken from the token's own header.
  A verifier that accepts `alg: none` is the classic way a JWT check gets
  talked out of checking anything; the test suite tries exactly that.
- **The `Bearer` prefix is required.** `authHeader.replace('Bearer ', '')`
  leaves a header that never had the prefix untouched, which accepted
  `Authorization: <token>` as readily as the real thing.
- **The signing key comes from the environment**, and the server refuses to
  start in production without one.

Still missing, because it needs more than a sample's worth of machinery: rate
limiting on `/login`. Nothing here slows down an attacker working through a
password list.

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.
* If you have suggestions for adding or removing projects, feel free to [open an issue](https://github.com/sadykhzadeh/koa-jwt-example/issues/new) to discuss it, or directly create a pull request after you edit the *README.md* file with necessary changes.
* Please make sure you check your spelling and grammar.
* Create individual PR for each suggestion.
* Please also read through the [Code Of Conduct](https://github.com/sadykhzadeh/koa-jwt-example/blob/main/CODE_OF_CONDUCT.md) before posting your first idea as well.

### Creating A Pull Request

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
