// CommonJS deterministic canonical JSON stringifier

function canonicalJsonStringify(obj) {
  if (obj === null || obj === undefined) {
    return "null";
  }
  if (typeof obj === "boolean" || typeof obj === "number") {
    return JSON.stringify(obj);
  }
  if (typeof obj === "string") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    const items = obj.map((item) => canonicalJsonStringify(item));
    return `[${items.join(",")}]`;
  }
  if (typeof obj === "object") {
    const sortedKeys = Object.keys(obj).sort();
    const entries = sortedKeys.map((key) => {
      const valStr = canonicalJsonStringify(obj[key]);
      return `${JSON.stringify(key)}:${valStr}`;
    });
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(obj);
}

module.exports = {
  canonicalJsonStringify,
};
