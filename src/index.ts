#!/usr/bin/env node
import { Command } from 'commander'
import tls from 'tls'
import fs from 'fs'
import path from 'path'
import https from 'https'
import http from 'http'
import readline from 'readline'
import crypto from 'crypto'

const API_VERSION = '1.0.3'

const MNEMONIC_LEN = 24
const MAX_WORD_LEN = 8

interface MnemonicWord {
	index: number
	word: string
}

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
				if (contentType?.match(/application\/\S*json/)) {
					d = JSON.parse(d.toString())
				} else if (contentType?.match(/text\/\S*plain/)) {
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
	const url = `https://${baseUrl}/riddleandcode/key-management/${API_VERSION}/auth/56`
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
	const url = `https://${baseUrl}/riddleandcode/key-management/${API_VERSION}/masterkey`
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
	const url = `https://${baseUrl}/riddleandcode/key-management/${API_VERSION}/masterkey`
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

// CRYPTO HELPERS

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
		const cb = (input: string) => {
			readline.cursorTo(process.stdout, 0, 0)
			readline.clearScreenDown(process.stdout)
			rl.close()
			rl.off('line', cb)
			accept(input)
		}
		rl.on('line', cb)
	})

const printNextSecretLine = (message: string): Promise<boolean> =>
	new Promise((accept, reject) => {
		process.stdin.resume()
		readline.cursorTo(process.stdout, 0, 0)
		readline.clearScreenDown(process.stdout)
		process.stdout.write(message)
		const cb = (input: string) => {
			if (input.includes('\n')) {
				readline.cursorTo(process.stdout, 0, 0)
				readline.clearScreenDown(process.stdout)
				process.stdin.off('data', cb)
				accept(true)
			}
		}
		process.stdin.on('data', cb)
	})

const readMnemonic = async () => {
	const currentWords = []
	while (currentWords.length < MNEMONIC_LEN) {
		const remainingWordLen: number = MNEMONIC_LEN - currentWords.length
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
	if (currentWords.length > MNEMONIC_LEN) {
		throw new Error('Mnemonic must be ${MNEMONIC_LEN} words long')
	}
	return currentWords.join(' ')
}

const mnemonicList = (mnemonic: string): MnemonicWord[] =>
	mnemonic
		.trim()
		.split(/\s+/)
		.map(
			(word, index): MnemonicWord => {
				return {
					word,
					index,
				}
			},
		)

const mnemonicHash = (mnemonic: string): string =>
	crypto.createHash('sha256').update(mnemonic).digest('hex').substring(0, 8)

const presentMnemonic = async (mnemonic: string, size: number) => {
	const words = mnemonicList(mnemonic)
	const header = `Mnemonic ID: ${mnemonicHash(mnemonic)}\n`
	let start = 0
	let end = Math.min(start + size, words.length)
	while (start < words.length) {
		const nextWords = words.slice(start, end)
		let descriptor
		if (end - start > 1) {
			descriptor = `Words ${start + 1}-${end}:\n`
		} else {
			descriptor = `Word: `
		}
		let nextWordsGrid = nextWords
			.map(({ word, index }) => {
				let padding = ' '.repeat(MAX_WORD_LEN - word.length)
				return `[${index + 1}] ${word}${padding}`
			})
			.join('\t')
		await printNextSecretLine(
			`${header}\nPress "Enter" to reveal next words...`,
		)
		await printNextSecretLine(
			`${header}\n${descriptor}${nextWordsGrid}\n\nPress "Enter" to clear...`,
		)
		start += size
		end = Math.min(start + size, words.length)
	}
}

const selectMnemonicWords = (
	mnemonic: string,
	wordNum: number,
): MnemonicWord[] => {
	let out: MnemonicWord[] = []
	let words = mnemonicList(mnemonic)
	let offset = MNEMONIC_LEN / wordNum + 1
	let next = 0
	while (out.length < wordNum) {
		next = (next + offset) % words.length
		out.push(words.splice(next, 1)[0])
	}
	out.sort((a, b) => a.index - b.index)
	return out
}

const verifyMnemonic = async (
	mnemonic: string,
	size: number,
	maxAttempts: number,
) => {
	const header = `Mnemonic ID: ${mnemonicHash(mnemonic)}\n`
	for (const { word, index } of selectMnemonicWords(mnemonic, size)) {
		console.log(index, word)
		let attempt = 0
		let successful = false
		while (attempt < maxAttempts) {
			let attemptsRemaining = ''
			if (attempt > 0) {
				attemptsRemaining = ` (${maxAttempts - attempt} attempts remaining)`
			}
			let data = (
				await readNextSecretLine(
					`${header}\nEnter Word ${index + 1}${attemptsRemaining}`,
				)
			).trim()
			if (data.length < 1) {
				continue
			}
			if (data == word) {
				successful = true
				break
			}
			attempt += 1
		}
		if (!successful) {
			throw new Error('Could not validate mnemonic')
		}
	}
}

// CLI Helper

const cliAction = (program: any, fn: () => Promise<void>) => async () => {
	try {
		if (program.wordNum < 1 || program.wordNum > MNEMONIC_LEN) {
			throw new Error(`'--word-num' must be between 1 and ${MNEMONIC_LEN}`)
		}
		if (program.validateNum < 1 || program.validateNum > MNEMONIC_LEN) {
			throw new Error(`'--validate-num' must be between 1 and ${MNEMONIC_LEN}`)
		}
		if (program.maxAttempts < 1) {
			throw new Error(`'--max-attempts' must be positive`)
		}
		await fn()
		process.exit(0)
	} catch (e) {
		let error
		if (e.data?.description) {
			error = e.data.description
		} else if (e.detail) {
			error = e.detail
		} else {
			try {
				error = e.toString()
			} catch (_) {
				error = 'Unknown error occured'
			}
		}
		console.error(error)
		process.exit(1)
	}
}

// COMMAND LINE PROGRAM

const program = new Command()

program.version(API_VERSION)

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
	MNEMONIC_LEN,
)
program.option(
	'-v, --verify-num <verifyNum>',
	'number of words to verify when generating or recovering a mnemonic',
	(val, lastVal) => parseInt(val),
	6,
)
program.option(
	'--max-attempts <maxAttempts>',
	'maxium number of attempts to verify a word',
	(val, lastVal) => parseInt(val),
	3,
)

program
	.command('token')
	.description('create a JWT token to be used for authentication')
	.action(
		cliAction(program, async () => {
			let res = await getToken({
				baseUrl: program.url,
				token: program.jwt,
				cert: program.cert,
				key: program.key,
				serverCa: program.serverCa,
			})
			console.log(res)
		}),
	)

program
	.command('generate')
	.description('generate a new keypair and mnemonic phrase')
	.action(
		cliAction(program, async () => {
			let { mnemonic } = await generateMnemonic({
				baseUrl: program.url,
				token: program.jwt,
				cert: program.cert,
				key: program.key,
				serverCa: program.serverCa,
			})
			await presentMnemonic(mnemonic, program.wordNum)
			await verifyMnemonic(mnemonic, program.verifyNum, program.maxAttempts)
		}),
	)

program
	.command('recover')
	.description('recover a keypair from an existing mnemonic phrase')
	.action(
		cliAction(program, async () => {
			let input = await readMnemonic()
			let { mnemonic } = await recoverMnemonic({
				baseUrl: program.url,
				mnemonic: input,
				token: program.jwt,
				cert: program.cert,
				key: program.key,
				serverCa: program.serverCa,
			})
			await verifyMnemonic(mnemonic, program.verifyNum, program.maxAttempts)
		}),
	)

program.parse(process.argv)
