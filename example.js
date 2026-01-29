import express from "express";
import { validateRequest, sizeLimiter, sanitizeRequest } from "./src/index.js";
import { orderSchema } from "./orderSchema.js";

const app = express();

app.post(
  "/order",
  sizeLimiter("1mb"),
  sanitizeRequest(),
  validateRequest({ body: orderSchema }),
  (req, res) => {
    res.json({
      success: true,
      data: req.body
    });
  }
);

app.listen(3000, () =>
  console.log("Server running on http://localhost:3000")
);
