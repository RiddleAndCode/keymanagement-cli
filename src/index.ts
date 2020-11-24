#!/usr/bin/env node
import { Command } from 'commander'
import ora from 'ora'
import pkginfo from 'pkginfo'

pkginfo(module, 'name', 'version')

const program = new Command()

program.version(module.exports.version)

// This is an example showing using an "ora" spinner for a long running command
program.command('run').action(() => {
	const spinner = ora()
	spinner.start('Loading...')
	setTimeout(() => {
		spinner.succeed('Step 1')
		spinner.start('Loading step 2...')

		setTimeout(() => {
			spinner.succeed('Step 2')
		}, 3000)
	}, 2000)
})

program.parse(process.argv)
