type Rule<Tag extends string, Parameters, RuleReturn, Context> = [Tag, (parameters: Parameters, context?: Context) => RuleReturn]
type ReturnOf<T extends (...args: any[]) => any> = Awaited<ReturnType<T>>

export type GatekeeperOptions<Parameters, RuleSet, Context = 'warn: not defined'> = {
  capture: (x: unknown) => Parameters,
  context?: (x: unknown) => Context,
  rules: RuleSet
}

export class GatekeeperUnauthorizedError extends Error {
  public constructor(message: string, public reason: Error, public rule: string = 'failcheck') {
    super(message)
  }
}

function gatekeeper<Parameters, Context, const RuleSet extends Rule<string, Parameters, unknown, Context>[]>(options: GatekeeperOptions<Parameters, RuleSet, Context>) {
  type Rules = {
    [Rule in RuleSet[number] as ReturnOf<Rule[1]> extends void ? never : Rule[0]]: ReturnOf<Rule[1]>
  }
  
  return {
    rules: options.rules,
    trust: async (parameters: Parameters, context?: Context): Promise<Rules> => {
      let currentRule: string | undefined = undefined
      
      context = options.context ? options.context(context) : undefined
      parameters = options.capture(parameters)
      
      try {
        const returnOfRuleSet = {} as Rules

        for (const [tag, rule] of options.rules) {
          currentRule = tag
          
          // @ts-expect-error TODO to type...
          returnOfRuleSet[tag as string] = await rule(parameters, context)
        }

        return returnOfRuleSet
      } catch (error: unknown) {
        if (error instanceof Error) {
          throw new GatekeeperUnauthorizedError('UNAUTHORIZED', error, currentRule)
        } else {
          throw new GatekeeperUnauthorizedError('UNAUTHORIZED', new Error(String(error)), currentRule)
        }
      }
    }
  }
}

export default gatekeeper
