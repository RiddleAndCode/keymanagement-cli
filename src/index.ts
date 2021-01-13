#!/usr/bin/env node
import { Command } from 'commander'
import pkginfo from 'pkginfo'
import tls from 'tls'
import fs from 'fs'
import path from 'path'
import https from 'https'
import http from 'http'
import readline from 'readline'

// HTTPS / JWT REQUESTS

const handleRes = (
	accept: (data: any) => void,
	reject: (err: any) => void,
	res: http.IncomingMessage,
) => {
	const isSuccessful =
		res.statusCode && res.statusCode >= 200 && res.statusCode < 400
	const contentLength = parseInt(res.headers['content-length'] || '0')
	if (contentLength > 0) {
		const contentType = res.headers['content-type']
		res.on('data', (d) => {
			try {
				if (contentType?.startsWith('application/json')) {
					d = JSON.parse(d.toString())
				} else if (contentType?.startsWith('text/plain')) {
					d = d.toString()
				}
			} catch (e) {
				isSuccessful ? reject(e) : reject(res.statusMessage)
			}
			isSuccessful ? accept(d) : reject(d)
		})
	} else {
		isSuccessful ? accept(undefined) : reject(res.statusMessage)
	}
}

const mutualTlsRequest = ({
	url,
	data,
	cert,
	key,
	serverCa,
	method,
}: {
	url: string
	data: string | Buffer | undefined
	cert: string
	key: string
	serverCa: string
	method: string
}): Promise<any> =>
	new Promise((accept, reject) => {
		const req = https.request(
			url,
			{
				method,
				headers: {
					Authorization: 'Bearer Mutual',
					'Content-Type': 'application/json',
				},
				key: fs.readFileSync(key),
				cert: fs.readFileSync(cert),
				ca: [fs.readFileSync(serverCa)],
			},
			(res) => handleRes(accept, reject, res),
		)
		req.on('error', (e) => {
			reject(e)
		})
		if (data !== undefined) {
			req.write(data)
		}
		req.end()
	})

const jwtRequest = ({
	url,
	data,
	token,
	serverCa,
	method,
}: {
	url: string
	data: string | Buffer | undefined
	token: string
	serverCa: string
	method: string
}): Promise<any> =>
	new Promise((accept, reject) => {
		const req = https.request(
			url,
			{
				method,
				headers: {
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json',
				},
				ca: [fs.readFileSync(serverCa)],
			},
			(res) => handleRes(accept, reject, res),
		)
		req.on('error', (e) => {
			reject(e)
		})
		if (data !== undefined) {
			req.write(data)
		}
		req.end()
	})

const request = ({
	url,
	data,
	token,
	cert,
	key,
	serverCa,
	method,
}: {
	url: string
	data: string | Buffer | undefined
	token: string | undefined
	cert: string
	key: string
	serverCa: string
	method: string
}): Promise<any> => {
	if (token !== undefined) {
		return jwtRequest({ url, data, token, serverCa, method })
	} else {
		return mutualTlsRequest({ url, data, cert, key, serverCa, method })
	}
}

// API CALLS

const getToken = async ({
	baseUrl,
	token,
	cert,
	key,
	serverCa,
}: {
	baseUrl: string
	token: string | undefined
	cert: string
	key: string
	serverCa: string
}): Promise<string> => {
	const url = `https://${baseUrl}/riddleandcode/key-management/1.0.3/auth/56`
	return await request({
		url,
		data: undefined,
		token,
		cert,
		key,
		serverCa,
		method: 'GET',
	})
}

const generateMnemonic = async ({
	baseUrl,
	token,
	cert,
	key,
	serverCa,
}: {
	baseUrl: string
	token: string | undefined
	cert: string
	key: string
	serverCa: string
}): Promise<{ mnemonic: string }> => {
	const url = `https://${baseUrl}/riddleandcode/key-management/1.0.3/masterkey`
	return await request({
		url,
		data: undefined,
		token,
		cert,
		key,
		serverCa,
		method: 'POST',
	})
}

const recoverMnemonic = async ({
	baseUrl,
	mnemonic,
	token,
	cert,
	key,
	serverCa,
}: {
	baseUrl: string
	mnemonic: string
	token: string | undefined
	cert: string
	key: string
	serverCa: string
}): Promise<{ mnemonic: string }> => {
	const url = `https://${baseUrl}/riddleandcode/key-management/1.0.3/masterkey`
	const data = JSON.stringify({ mnemonic })
	return await request({
		url,
		data,
		token,
		cert,
		key,
		serverCa,
		method: 'PATCH',
	})
}

// MNEMONIC I/O

const readNextSecretLine = (question: string): Promise<string> =>
	new Promise((accept, reject) => {
		process.stdin.read()
		readline.cursorTo(process.stdout, 0, 0)
		readline.clearScreenDown(process.stdout)
		process.stdout.write(`${question}: `)
		var rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		})
		rl.on('line', (input) => {
			readline.cursorTo(process.stdout, 0, 0)
			readline.clearScreenDown(process.stdout)
			rl.close()
			accept(input)
		})
	})

const printNextSecretLine = (message: string): Promise<boolean> =>
	new Promise((accept, reject) => {
		process.stdin.resume()
		readline.cursorTo(process.stdout, 0, 0)
		readline.clearScreenDown(process.stdout)
		process.stdout.write(message)
		process.stdin.on('data', (input) => {
			if (input.includes('\n')) {
				readline.cursorTo(process.stdout, 0, 0)
				readline.clearScreenDown(process.stdout)
				accept(true)
			}
		})
	})

const readMnemonic = async () => {
	const desiredLen = 24
	const currentWords = []
	while (currentWords.length < desiredLen) {
		const remainingWordLen: number = desiredLen - currentWords.length
		let data = (
			await readNextSecretLine(
				`Enter mnemonic...\nNext words (${remainingWordLen} remaining)`,
			)
		).trim()
		if (data.length < 1) {
			continue
		}
		currentWords.push(...data.split(/\s+/))
		process.stdout.write('\r\x1b[K')
	}
	if (currentWords.length > desiredLen) {
		throw new Error('Mnemonic must be 24 words long')
	}
	return currentWords.join(' ')
}

const presentMnemonic = async (mnemonic: string, size: number) => {
	const words = mnemonic.trim().split(/\s+/)
	let start = 0
	let end = Math.min(start + size, words.length)
	while (start < words.length) {
		const nextWords = words.slice(start, end)
		let descriptor
		if (end - start > 1) {
			descriptor = `Words ${start + 1}-${end}`
		} else {
			descriptor = `Word ${start + 1}`
		}
		await printNextSecretLine(`Press "Enter" to reveal next words...`)
		await printNextSecretLine(
			`${descriptor}: ${nextWords.join(' ')}\nPress "Enter" to clear...`,
		)
		start += size
		end = Math.min(start + size, words.length)
	}
}

// COMMAND LINE PROGRAM

pkginfo(module, 'name', 'version')

const program = new Command()

program.version(module.exports.version)

program.option(
	'-u, --url <url>',
	'the url of the keymanagement service',
	'localhost:8080',
)
program.option(
	'-c, --cert <cert>',
	'the TLS certificate used for authentication',
	'./ssl/client-cert.pem',
)
program.option(
	'-k, --key <key>',
	'the TLS key used for authentication',
	'./ssl/client-key.pem',
)
program.option(
	'-a, --server-ca <serverCa>',
	'the certificate authority of the server',
	'./ssl/server-ca.pem',
)
program.option(
	'-j, --jwt <token>',
	'the JSON Web Token used for authentication',
)
program.option(
	'-n, --word-num <wordNum>',
	'number of words to present at a time when displaying mnemonic',
	(val, lastVal) => parseInt(val),
	24,
)

program
	.command('token')
	.description('create a JWT token to be used for authentication')
	.action(async () => {
		try {
			let res = await getToken({
				baseUrl: program.url,
				token: program.jwt,
				cert: program.cert,
				key: program.key,
				serverCa: program.serverCa,
			})
			console.log(res)
		} catch (e) {
			console.log(e.data?.description || e)
			process.exit(1)
		}
	})

program
	.command('generate')
	.description('generate a new keypair and mnemonic phrase')
	.action(async () => {
		try {
			let { mnemonic } = await generateMnemonic({
				baseUrl: program.url,
				token: program.jwt,
				cert: program.cert,
				key: program.key,
				serverCa: program.serverCa,
			})
			await presentMnemonic(mnemonic, program.wordNum)
			process.exit(0)
		} catch (e) {
			console.log(e.data?.description || e)
			process.exit(1)
		}
	})

program
	.command('recover')
	.description('recover a keypair from an existing mnemonic phrase')
	.action(async () => {
		let input
		try {
			input = await readMnemonic()
			let { mnemonic } = await recoverMnemonic({
				baseUrl: program.url,
				mnemonic: input,
				token: program.jwt,
				cert: program.cert,
				key: program.key,
				serverCa: program.serverCa,
			})
			await presentMnemonic(mnemonic, program.wordNum)
			process.exit(0)
		} catch (e) {
			console.log(e.toString())
			process.exit(1)
		}
	})

program.parse(process.argv)
