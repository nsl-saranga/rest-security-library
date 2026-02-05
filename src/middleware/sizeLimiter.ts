import bodyParser from "body-parser";
import type { RequestHandler } from "express";

export function sizeLimiter(limit = "1mb"): RequestHandler {
  return bodyParser.json({
    limit,
    strict: true,
    type: "application/json"
  });
}

