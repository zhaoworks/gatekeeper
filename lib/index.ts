/**
 * Represents a rule in the gatekeeper system.
 * @template Tag - The name of the rule.
 * @template Parameters - The input parameters the rule uses.
 * @template RuleReturn - The type of the result returned by the rule.
 * @template Context - Additional context that the rule might need (optional).
 */
type Rule<
  Tag extends string,
  Parameters,
  RuleReturn,
  Context = unknown,
> = readonly [
  Tag,
  (
    parameters: Parameters,
    context: Context,
  ) => RuleReturn | Promise<RuleReturn>,
];

/**
 * Utility type that gets the return type of a function, including if it's a Promise.
 */
// biome-ignore lint/suspicious/noExplicitAny: generic function.
type  ReturnOf<T extends (...args: any[]) => any> = Awaited<ReturnType<T>>;

/**
 * Options for setting up the gatekeeper.
 * @template Parameters - The input parameters the gatekeeper will handle.
 * @template Context - Additional context the gatekeeper might use (optional).
 * @template RuleSet - A list of rules that the gatekeeper will follow.
 */
export type GatekeeperOptions<
  Parameters,
  Context = unknown,
  RuleSet extends ReadonlyArray<Rule<string, Parameters, unknown, Context>> = Rule<
    string,
    Parameters,
    unknown,
    Context
  >[],
> = {
  capture: (x: unknown) => Parameters;
  context?: (x: unknown) => Context;
  rules: RuleSet;
};

/**
 * Error thrown when gatekeeper authorization fails.
 */
export class GatekeeperUnauthorizedError extends Error {
  public constructor(
    message: string,
    public reason: Error,
    public rule: string = 'failcheck' as string,
  ) {
    super(message);
  }
}

/**
 * Creates a custom rule for the gatekeeper.
 * @template Tag - The name of the rule.
 * @template Parameters - The input parameters the rule uses.
 * @template RuleReturn - The type of the result returned by the rule.
 * @template Context - Additional context that the rule might need (optional).
 * @param tag - The name of the rule.
 * @param ruleFn - The function that contains the rule's logic.
 * @returns A Rule tuple.
 */
export function customRule<
  Tag extends string,
  Parameters,
  RuleReturn,
  Context = unknown,
>(
  tag: Tag,
  ruleFn: (
    parameters: Parameters,
    context: Context,
  ) => RuleReturn | Promise<RuleReturn>,
): Rule<Tag, Parameters, RuleReturn, Context> {
  return [tag, ruleFn] as const;
}

/**
 * Creates a gatekeeper instance using the specified options.
 * @template Parameters - The input parameters the gatekeeper will handle.
 * @template Context - Additional context the gatekeeper might use (optional).
 * @template RuleSet - A list of rules that the gatekeeper will follow.
 * @param options - The configuration options for the gatekeeper.
 * @returns An object with the gatekeeper rules and a trust function.
 */
function gatekeeper<
  Parameters,
  Context = unknown,
  RuleSet extends ReadonlyArray<Rule<string, Parameters, unknown, Context>> = Rule<
    string,
    Parameters,
    unknown,
    Context
  >[],
>(options: GatekeeperOptions<Parameters, Context, RuleSet>) {
  type Rules = {
    [R in RuleSet[number] as ReturnOf<R[1]> extends void
      ? never
      : R[0]]: ReturnOf<R[1]>;
  };

  return {
    rules: options.rules,
    trust: async (input: Parameters, context?: Context): Promise<Rules> => {
      let currentRule: string | undefined = undefined;

      const validatedContext = options.context
        ? options.context(context)
        : undefined;
        
      const parameters = options.capture(input);

      try {
        const returnOfRuleSet = {} as Rules;

        for (const [tag, rule] of options.rules) {
          currentRule = tag;

          const result = await rule(parameters, validatedContext as Context);
          if (result !== undefined) {
            (returnOfRuleSet as Record<string, unknown>)[tag] = result;
          }
        }

        return returnOfRuleSet;
      } catch (error: unknown) {
        if (error instanceof Error) {
          throw new GatekeeperUnauthorizedError(
            'UNAUTHORIZED',
            error,
            currentRule,
          );
        }

        throw new GatekeeperUnauthorizedError(
          'UNAUTHORIZED',
          new Error(String(error)),
          currentRule,
        );
      }
    },
  };
}

export default gatekeeper;
