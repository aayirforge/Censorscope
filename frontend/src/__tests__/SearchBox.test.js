const test = require("node:test");
const assert = require("node:assert");

// Import the domain validation function logic for testing
function validateDomainInput(raw) {
  if (!raw || !raw.trim()) {
    return { isValid: false, domain: "", error: "Please enter a domain name." };
  }

  let cleaned = raw.trim().toLowerCase();

  // Strip scheme if entered
  if (cleaned.startsWith("http://")) cleaned = cleaned.slice(7);
  if (cleaned.startsWith("https://")) cleaned = cleaned.slice(8);

  // Strip credentials
  if (cleaned.includes("@")) cleaned = cleaned.split("@")[1];

  // Strip path/query/fragment
  cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0];

  // Strip port
  if (cleaned.includes(":")) cleaned = cleaned.split(":")[0];

  // Strip trailing dot
  cleaned = cleaned.replace(/\.+$/, "");

  if (!cleaned) {
    return { isValid: false, domain: "", error: "Invalid domain format." };
  }

  // Label and structure checks
  const labels = cleaned.split(".");
  if (labels.length < 2) {
    return { isValid: false, domain: cleaned, error: "Please enter a full domain including top-level domain (e.g., example.com)." };
  }

  const labelRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  for (const label of labels) {
    if (!label) {
      return { isValid: false, domain: cleaned, error: "Domain cannot contain empty labels or consecutive dots." };
    }
    if (!labelRegex.test(label)) {
      return { isValid: false, domain: cleaned, error: `Invalid characters in domain segment: '${label}'.` };
    }
  }

  const tld = labels[labels.length - 1];
  if (/^\d+$/.test(tld)) {
    return { isValid: false, domain: cleaned, error: "Top-level domain cannot be purely numeric." };
  }

  return { isValid: true, domain: cleaned };
}

test("validateDomainInput cleans schemes and paths correctly", () => {
  const result = validateDomainInput("https://thepiratebay.org/browse/100");
  assert.strictEqual(result.isValid, true);
  assert.strictEqual(result.domain, "thepiratebay.org");
});

test("validateDomainInput cleans ports and trailing dots", () => {
  const result = validateDomainInput("wikipedia.org:443.");
  assert.strictEqual(result.isValid, true);
  assert.strictEqual(result.domain, "wikipedia.org");
});

test("validateDomainInput rejects invalid formats", () => {
  assert.strictEqual(validateDomainInput("").isValid, false);
  assert.strictEqual(validateDomainInput("   ").isValid, false);
  assert.strictEqual(validateDomainInput("invalid_domain").isValid, false);
  assert.strictEqual(validateDomainInput("example..com").isValid, false);
  assert.strictEqual(validateDomainInput("test.123").isValid, false);
});
