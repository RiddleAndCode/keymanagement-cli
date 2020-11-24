#!/usr/bin/env node
import { Command } from 'commander'
import ora from 'ora'
import pkginfo from 'pkginfo'
import tls from 'tls'
import fs from 'fs'
import path from 'path'
import https from 'https'

export const twoWayTlsRequest = ({
	url,
	cert,
	key,
	serverCa,
	method,
}: {
	url: string
	cert: string
	key: string
	serverCa: string
	method: string
}): Promise<Buffer> =>
	new Promise((accept, reject) => {
		const req = https.request(
			url,
			{
				method,
				headers: { Authorization: 'Bearer Mutual' },
				key: fs.readFileSync(key),
				cert: fs.readFileSync(cert),
				ca: [fs.readFileSync(serverCa)],
			},
			(res) => {
				res.on('data', (d) => {
					accept(d)
				})
			},
		)
		req.on('error', (e) => {
			reject(e)
		})
		req.end()
	})

export const token = async ({
	baseUrl,
	cert,
	key,
	serverCa,
}: {
	baseUrl: string
	cert: string
	key: string
	serverCa: string
}): Promise<string> => {
	const url = `https://${baseUrl}/riddleandcode/key-management/0.0.17/auth/56`
	const data = await twoWayTlsRequest({
		url,
		cert,
		key,
		serverCa,
		method: 'GET',
	})
	return data.toString()
}

export const generate = async ({
	baseUrl,
	cert,
	key,
	serverCa,
}: {
	baseUrl: string
	cert: string
	key: string
	serverCa: string
}): Promise<{ mnemonic: string }> => {
	const url = `https://${baseUrl}/riddleandcode/key-management/0.0.17/masterkey`
	const data = await twoWayTlsRequest({
		url,
		cert,
		key,
		serverCa,
		method: 'POST',
	})
	return JSON.parse(data.toString())
}

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

program.command('token').action(async () => {
	let res = await token({
		baseUrl: program.url,
		cert: program.cert,
		key: program.key,
		serverCa: program.serverCa,
	})
	console.log(res)
})

program.command('generate').action(async () => {
	let { mnemonic } = await generate({
		baseUrl: program.url,
		cert: program.cert,
		key: program.key,
		serverCa: program.serverCa,
	})
	console.log(mnemonic)
})

program.parse(process.argv)
