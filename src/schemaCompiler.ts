import Ajv, { type AnySchema, type ValidateFunction } from "ajv";
import addFormats from "ajv-formats";

export const ajv = new Ajv({
  allErrors: true,
  strict: true,
  coerceTypes: false,
  removeAdditional: false
});

addFormats(ajv);

export function compileSchema(schema: AnySchema): ValidateFunction {
  return ajv.compile(schema);
}

