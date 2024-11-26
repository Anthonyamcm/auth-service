import validator from 'validator';

export function validateIdentifier(
  identifier: string,
  isEmail: boolean
): boolean {
  if (isEmail) {
    return validator.isEmail(identifier);
  } else {
    return validator.isMobilePhone(identifier, 'any');
  }
}

export function validatePassword(password: string): boolean {
  // Implement your password policy here
  return validator.isStrongPassword(password, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 0,
  });
}

export function validateCode(code: string): boolean {
  // Assuming the code is a 6-digit number
  return (
    validator.isLength(code, { min: 6, max: 6 }) && validator.isNumeric(code)
  );
}

export function validateDate(date: Date): boolean {
  return date instanceof Date && !isNaN(date.getTime());
}
