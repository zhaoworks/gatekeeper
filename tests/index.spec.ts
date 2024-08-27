import { expect, test, describe } from 'bun:test';
import gatekeeper, { customRule, GatekeeperUnauthorizedError } from '../lib';

describe('Gatekeeper', () => {
  test('should create a gatekeeper instance', () => {
    const instance = gatekeeper({
      capture: (x) => x as { userId: string },
      rules: [],
    });

    expect(instance).toHaveProperty('rules');
    expect(instance).toHaveProperty('trust');
  });

  test('should pass all rules and return expected results', async () => {
    const instance = gatekeeper({
      capture: (x: unknown) => x as { userId: string },
      rules: [
        customRule(
          'checkUserId',
          (params: { userId: string }) => params.userId === 'admin',
        ),
        customRule('getRole', (params: { userId: string }) =>
          params.userId === 'admin' ? 'admin' : 'user',
        ),
      ],
    });

    const result = await instance.trust({ userId: 'admin' });
    expect(result).toEqual({
      checkUserId: true,
      getRole: 'admin',
    });
  });

  test('should fail on first failing rule', async () => {
    const instance = gatekeeper({
      capture: (x: unknown) => x as { userId: string },
      rules: [
        customRule('checkUserId', (params: { userId: string }) => {
          if (params.userId !== 'admin') throw new Error('Not admin');
          return true;
        }),
        customRule('neverReached', () => 'This should not be reached'),
		customRule('_', (params: { userId: string }) => ({ params }))
      ],
    });

    await expect(instance.trust({ userId: 'user' })).rejects.toThrow(
      GatekeeperUnauthorizedError,
    );
  });

  test('should handle async rules', async () => {
    const instance = gatekeeper({
      capture: (x: unknown) => x as { userId: string },
      rules: [
        customRule('asyncCheck', async (params: { userId: string }) => {
          await new Promise((resolve) => setTimeout(resolve, 10));
          return params.userId === 'admin';
        }),
      ],
    });

    const result = await instance.trust({ userId: 'admin' });
    expect(result).toEqual({ asyncCheck: true });
  });

  test('should use context if provided', async () => {
    const instance = gatekeeper({
      capture: (x: unknown) => x as { userId: string },
      context: (x: unknown) => x as { isSpecialMode: boolean },
      rules: [
        customRule(
          'contextAwareCheck',
          (params: { userId: string }, context: { isSpecialMode: boolean }) => {
            if (context?.isSpecialMode) {
              return 'special';
            }
            return params.userId === 'admin' ? 'admin' : 'user';
          },
        ),
      ],
    });

    const regularResult = await instance.trust({ userId: 'user' });
    expect(regularResult).toEqual({ contextAwareCheck: 'user' });

    const specialResult = await instance.trust(
      { userId: 'user' },
      { isSpecialMode: true },
    );
    expect(specialResult).toEqual({ contextAwareCheck: 'special' });
  });

  test('should handle rules with void return', async () => {
    const instance = gatekeeper({
      capture: (x) => x as { userId: string },
      rules: [
        customRule('voidRule', () => {
          /* do nothing */
        }),
        customRule('normalRule', () => true),
      ],
    });

    const result = await instance.trust({ userId: 'admin' });
    expect(result).toEqual({ normalRule: true });
    expect(result).not.toHaveProperty('voidRule');
  });

  test('should provide correct error information on failure', async () => {
    const instance = gatekeeper({
      capture: (x) => x as { userId: string },
      rules: [
        customRule('failingRule', () => {
          throw new Error('Custom error');
        }),
      ],
    });

    try {
      await instance.trust({ userId: 'admin' });
    } catch (error) {
      expect(error).toBeInstanceOf(GatekeeperUnauthorizedError);
      if (error instanceof GatekeeperUnauthorizedError) {
        expect(error.message).toBe('UNAUTHORIZED');
        expect(error.reason.message).toBe('Custom error');
        expect(error.rule).toBe('failingRule');
      }
    }
  });
});
