# Validator Library - Core Functions

## Installation

```bash
npm install validator
```

## Import

```javascript
const validator = require("validator");
```

## String Validation

### `validator.isEmail(str)`

```javascript
validator.isEmail("test@example.com"); // true
validator.isEmail("invalid-email"); // false
```

### `validator.isEmpty(str)`

```javascript
validator.isEmpty(""); // true
validator.isEmpty("text"); // false
```

### `validator.isLength(str, options)`

```javascript
validator.isLength("hello", { min: 3, max: 10 }); // true
validator.isLength("hi", { min: 3 }); // false
```

### `validator.isAlpha(str)`

```javascript
validator.isAlpha("HelloWorld"); // true
validator.isAlpha("Hello123"); // false
```

### `validator.isAlphanumeric(str)`

```javascript
validator.isAlphanumeric("Hello123"); // true
validator.isAlphanumeric("Hello@"); // false
```

### `validator.isNumeric(str)`

```javascript
validator.isNumeric("12345"); // true
validator.isNumeric("123a"); // false
```

## URL & Network

### `validator.isURL(str)`

```javascript
validator.isURL("https://google.com"); // true
validator.isURL("invalid-url"); // false
```

### `validator.isIP(str)`

```javascript
validator.isIP("192.168.1.1"); // true
validator.isIP("invalid-ip"); // false
```

### `validator.isMACAddress(str)`

```javascript
validator.isMACAddress("ab:cd:ef:01:23:45"); // true
```

## Date & Time

### `validator.isDate(str)`

```javascript
validator.isDate("2023-12-25"); // true
validator.isDate("invalid"); // false
```

### `validator.isBefore(str, date)`

```javascript
validator.isBefore("2023-01-01", "2023-12-31"); // true
```

### `validator.isAfter(str, date)`

```javascript
validator.isAfter("2023-12-31", "2023-01-01"); // true
```

## Numeric Validation

### `validator.isInt(str, options)`

```javascript
validator.isInt("123"); // true
validator.isInt("123", { min: 0, max: 200 }); // true
validator.isInt("999", { max: 500 }); // false
```

### `validator.isFloat(str, options)`

```javascript
validator.isFloat("123.45"); // true
validator.isFloat("123.45", { min: 0, max: 200 }); // true
```

### `validator.isCurrency(str)`

```javascript
validator.isCurrency("$123.45"); // true
validator.isCurrency("123"); // false
```

## Credit Card & Financial

### `validator.isCreditCard(str)`

```javascript
validator.isCreditCard("4111111111111111"); // true (Visa format)
```

### `validator.isIBAN(str)`

```javascript
validator.isIBAN("GB82WEST12345698765432"); // true
```

## Text Patterns

### `validator.isStrongPassword(str, options)`

```javascript
validator.isStrongPassword("MyPass123!"); // true
validator.isStrongPassword("weak"); // false

// With options
validator.isStrongPassword("pass", {
  minLength: 8,
  minLowercase: 1,
  minUppercase: 1,
  minNumbers: 1,
  minSymbols: 1,
}); // false
```

### `validator.matches(str, pattern)`

```javascript
validator.matches("hello123", /^[a-z0-9]+$/); // true
validator.matches("Hello!", /^[a-z0-9]+$/); // false
```

### `validator.isUUID(str)`

```javascript
validator.isUUID("550e8400-e29b-41d4-a716-446655440000"); // true
```

## Sanitization Functions

### `validator.escape(str)`

```javascript
validator.escape('<script>alert("xss")</script>');
// Returns: &lt;script&gt;alert(&quot;xss&quot;)&lt;&#x2F;script&gt;
```

### `validator.trim(str, chars)`

```javascript
validator.trim("  hello  "); // 'hello'
validator.trim("++hello++", "+"); // 'hello'
```

### `validator.normalizeEmail(str)`

```javascript
validator.normalizeEmail("Test@Gmail.com"); // 'test@gmail.com'
```

### `validator.toInt(str)`

```javascript
validator.toInt("123"); // 123
validator.toInt("123.45"); // 123
```

### `validator.toFloat(str)`

```javascript
validator.toFloat("123.45"); // 123.45
```

### `validator.toBoolean(str)`

```javascript
validator.toBoolean("true"); // true
validator.toBoolean("false"); // false
validator.toBoolean("1"); // true
validator.toBoolean("0"); // false
```

## Common Usage Pattern

```javascript
// Validate user input
const email = "user@example.com";
const password = "MyPass123!";

if (!validator.isEmail(email)) {
  throw new Error("Invalid email");
}

if (!validator.isStrongPassword(password)) {
  throw new Error("Weak password");
}

// Sanitize input
const cleanEmail = validator.normalizeEmail(email);
const safeText = validator.escape(userInput);
```
