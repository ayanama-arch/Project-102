const { z } = require("zod");

const userSchema = z.object({
  fullName: z
    .string()
    .min(2, { message: "Name must be at least 2 characters." })
    .max(50, { message: "Name must be at most 50 characters." }),

  email: z.string().email({ message: "Invalid email format." }),

  password: z
    .string()
    .min(8, { message: "Password must be at least 8 characters." })
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
      {
        message:
          "Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.",
      }
    ),
});

function validateUserInput({ fullName, email, password }) {
  const result = userSchema.safeParse({ fullName, email, password });

  if (result.success) {
    return {
      isValid: true,
      data: result.data,
    };
  }

  const errors = result.error.errors.map((err) => ({
    field: err.path[0],
    message: err.message,
  }));

  return {
    isValid: false,
    errors,
  };
}

module.exports = validateUserInput;
