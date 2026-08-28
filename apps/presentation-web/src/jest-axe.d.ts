declare module 'jest-axe' {
  export interface AxeResults {
    violations: unknown[]
  }

  export function axe(container: Element): Promise<AxeResults>
}
