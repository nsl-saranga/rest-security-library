import express, { type Request, type Response } from "express";
import {
  validateRequest,
  sizeLimiter,
  sanitizeRequest
} from "./src/index";
// import { orderSchema } from "./orderSchema"; // Example placeholder

const app = express();

app.post(
  "/order",
  sizeLimiter("1mb"),
  sanitizeRequest(),
  // validateRequest({ body: orderSchema }),
  (req: Request, res: Response) => {
    res.json({
      success: true,
      data: req.body
    });
  }
);

app.listen(3000, () =>
  console.log("Server running on http://localhost:3000")
);

