import bodyParser from "body-parser";

export function sizeLimiter(limit = "1mb") {
  return bodyParser.json({
    limit,
    strict: true,
    type: "application/json"
  });
}
