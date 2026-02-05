import type { Request, Response, NextFunction } from "express";
import type { ValidateFunction } from "ajv";
import { compileSchema } from "./schemaCompiler";
import { formatErrors } from "../utils/errors";

type Location = "body" | "query" | "params";

export interface RequestSchemas {
  body?: object;
  query?: object;
  params?: object;
}

type ValidatorFn = ValidateFunction;

export function validateRequest({ body, query, params }: RequestSchemas) {
  const validators: Partial<Record<Location, ValidatorFn>> = {
    body: body ? compileSchema(body) : undefined,
    query: query ? compileSchema(query) : undefined,
    params: params ? compileSchema(params) : undefined
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    for (const [location, validate] of Object.entries(validators) as [
      Location,
      ValidatorFn | undefined
    ][]) {
      if (!validate) continue;

      const valid = validate((req as any)[location]); // eslint-disable-line @typescript-eslint/no-explicit-any

      if (!valid) {
        res.status(400).json({
          error: "Invalid request",
          location,
          details: formatErrors(validate.errors || [])
        });
        return;
      }
    }

    next();
  };
}

