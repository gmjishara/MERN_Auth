export default function validatePassword(password) {
  const errors = [];

  // Minimum length
  if (password.length < 8) {
    errors.push("Password must be at least 8 characters long.");
  }

  // Uppercase letters
  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter (A-Z).");
  }

  // Lowercase letters
  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter (a-z).");
  }

  // Numbers
  if (!/[0-9]/.test(password)) {
    errors.push("Password must contain at least one number (0-9).");
  }

  // Special characters
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push(
      "Password must contain at least one special character (!@#$%^&*)."
    );
  }

  // Common passwords (add more to this list)
  const commonPasswords = ["password", "12345678", "qwerty", "admin"];
  if (commonPasswords.includes(password.toLowerCase())) {
    errors.push("Password is too common or easily guessable.");
  }

  // Whitespace check
  if (/\s/.test(password)) {
    errors.push("Password must not contain spaces.");
  }

  return {
    isValid: errors.length === 0,
    message: errors.length > 0 ? errors[0] : "Password is valid.",
  };
}
