import { describe, it, expect } from 'bun:test'

import gatekeeper, { GatekeeperUnauthorizedError } from '../lib'

const FAILED_ERROR = new Error('Something is wrong...')

describe('gatekeeper', () => {
	const { rules, trust } = gatekeeper({
		capture: (type) => type as { authorization: string },
		context: (type) => type as { role?: string } & { error?: boolean },
		rules: [
			['organization', async ({ authorization }) => ({ authorization, id: 1 })],
			['user', async ({}, x) => ({ id: 1, role: x?.role })],
			['error', async (_unused, ctx) => { if (ctx?.error === true) throw FAILED_ERROR }],
			['hide', async () => {}],
		]
	})
	
	it('does not have extra rules', () => {
		expect(rules).toHaveLength(4)
	})

	it('apply all ok rules and return object', async () => {
		const rules = await trust({ authorization: 'Bearer tokn_123123' })

		expect(rules).toMatchObject({
			organization: { id: 1 },
			user: { id: 1 },
		})
	})
	
	it('apply fail rule and return object immediately', async () => {
		const fallibleTrust = async () => await trust({ authorization: 'Bearer tokn_123123' }, { error: true })

		expect(fallibleTrust).toThrowError('UNAUTHORIZED')
	})

	it('has extra details when failed', async () => {
		const fallibleTrust = await trust({ authorization: 'Bearer tokn_123123' }, { error: true })
			.catch((error: GatekeeperUnauthorizedError) => error) as GatekeeperUnauthorizedError

		expect(fallibleTrust.rule).toBe('error')
		expect(fallibleTrust.reason).toBe(FAILED_ERROR)
	})
})

