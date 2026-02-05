// Example JSON Schema for an order payload.
// You can change this to match your real domain model.

export const orderSchema = {
  type: "object",
  required: ["id", "items", "total"],
  properties: {
    id: { type: "string", minLength: 1 },
    items: {
      type: "array",
      minItems: 1,
      items: {
        type: "object",
        required: ["sku", "quantity"],
        properties: {
          sku: { type: "string", minLength: 1 },
          quantity: { type: "integer", minimum: 1 }
        },
        additionalProperties: false
      }
    },
    total: { type: "number", minimum: 0 }
  },
  additionalProperties: false
} as const;

