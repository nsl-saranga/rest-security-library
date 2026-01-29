import { compileSchema } from "./schemaCompiler.js";
import { formatErrors } from "./errors.js";

export function validateRequest({ body, query, params }) {
  const validators = {
    body: body && compileSchema(body),
    query: query && compileSchema(query),
    params: params && compileSchema(params)
  };

  return (req, res, next) => {
    for (const [location, validate] of Object.entries(validators)) {
      if (!validate) continue;

      const valid = validate(req[location]);

      if (!valid) {
        return res.status(400).json({
          error: "Invalid request",
          location,
          details: formatErrors(validate.errors)
        });
      }
    }

    next();
  };
}
