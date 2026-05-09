export class A2AError extends Error {
  constructor(
    message: string,
    public readonly code?: number,
    public readonly httpStatus?: number,
  ) {
    super(message)
    this.name = 'A2AError'
  }
}
