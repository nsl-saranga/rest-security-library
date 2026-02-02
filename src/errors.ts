import type { ErrorObject } from "ajv";

export interface FormattedError {
  field: string;
  message?: string;
}

export function formatErrors(errors: ErrorObject[] = []): FormattedError[] {
  return errors.map((err) => ({
    field: err.instancePath || "(root)",
    message: err.message
  }));
}

