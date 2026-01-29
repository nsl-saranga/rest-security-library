export function formatErrors(errors) {
  return errors.map(err => ({
    field: err.instancePath || "(root)",
    message: err.message
  }));
}
