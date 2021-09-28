# keymanagement-cli

A small CLI to generate / recover keys and tokens from the Key Management service

## Installing

1. Install dependencies

```bash
yarn install
```

2. Run the build command to transpile the Typescript to Javascript. This will output to the `./dist` folder.

```bash
yarn build
```

3. To enable running CLI commands locally link the project to your global NPM folder. This must be done with `npm link` since `yarn link` does not link `bin` files.

```bash
npm link --no-package-lock
```

## Usage

Once the bin is linked you can learn more about its usage by running

```bash
keyman --help
```

## Certificates

The CLI uses client side TLS for authentication (as well as JWT if the `--token` flag is specified). If you generated certificates on the server (using `make certificates`) then the certificates should match one to one as follows

| Server                | CLI                   |
| --------------------- | --------------------- |
| ./ssl/ca-cert.pem     | ./ssl/server-ca.pem   |
| ./ssl/client-cert.pem | ./ssl/client-cert.pem |
| ./ssl/client-key.pem  | ./ssl/client-key.pem  |

Although of course, the server should be configurable against any client CA, and vice-versa

## Step by step guide

1. Create client certificates 
For self-signed certificates use the script provided in [/utilities](/utilities).
Send the file `client-ca-cert.pem` to Riddle&Code.
2. Get CA certificate from Riddle&Code for the instance to be used, rename it to `rnc-ca-cert.pem` and store it in the directory `ssl`.
3. Generate a new keypair and save the mnemonic phrase
`keyman -u <server> -c ssl/client-cert.pem -k ssl/client-key.pem -a ssl/rnc-ca-cert.pem generate`
4. Recover from the mnemonic phrase
`keyman -u ckm-s1s-dev.r3c.network:8443 -c ssl/client-cert.pem -k ssl/client-key.pem -a ssl/rnc-ca-cert.pem recover`
5. Generate a token for authentication
`keyman -u <server> -c ssl/client-cert.pem -k ssl/client-key.pem -a ssl/rnc-ca-cert.pem token` 
