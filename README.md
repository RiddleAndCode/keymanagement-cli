# typescript-cli-template

This is intended to be a starter template repo for creating CLI programs with Typescript. The template project uses [commander.js](https://github.com/tj/commander.js) as the library for wiring up the CLI commands and comes with Typescript, ESLint and Prettier preconfigured. The [ora](https://github.com/sindresorhus/ora) library is also preinstalled for showing spinners.

## Getting Started

1. Use GitHub's "[Use this Template](https://github.com/justinneff/typescript-cli-template/generate)" feature to genrate your own repo from this one.
2. Clone your repo locally
3. Install dependencies

```bash
yarn install
```

4. Edit the `package.json` file to update the `bin` links to change the name of the generated binary to suit your needs.

```json
"bin": {
	"test-prog": "./dist/index.js"
}
```

5. Run the build command to transpile the Typescript to Javascript. This will output to the `./dist` folder.

```bash
yarn build
```

6. To enable running CLI commands locally link the project to your global NPM folder. This must be done with `npm link` since `yarn link` does not link `bin` files.

```bash
npm link --no-package-lock
```

7. If you rename or add additional `bin` files, you will need to unlink and relink your project.

```bash
npm unlink
npm link --no-package-lock
```
