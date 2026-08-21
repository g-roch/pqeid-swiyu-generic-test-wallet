/**
 * PQEID: console-only instrumentation to compare wire sizes between the PQC crypto path
 * (ML-DSA-44 / X-Wing) and the classical path (ES256 / ECDH-ES) the wallet may end up
 * talking to (see holder-key.ts::detectIssuerDpopAlg). Not user-facing UI - a research aid
 * for manually comparing runs against a PQC issuer/verifier vs a classical one.
 *
 * Measures the UTF-8 byte length of the actual protocol artifact being exchanged (a JWT, a
 * JWE, a JSON body, a resolved DID document...), never raw HTTP wire bytes: request/response
 * *headers* (Content-Type, Accept, Authorization, TLS record overhead...) are deliberately
 * excluded, since they're transport-level noise that doesn't change between PQC and
 * classical. Anything that IS semantically part of what a verifier/issuer needs (a DPoP
 * proof, even though it's carried as a header *value*; a DID Document fetched to resolve a
 * verification key; a status list) is still logged, because the byte cost of that artifact
 * is exactly what this instrumentation exists to compare.
 */
export function logMessageSize(
  step: "Émission" | "Vérification",
  label: string,
  includes: string,
  content: unknown,
): void {
  console.log(
    `[pqeid-size] ${step} — ${label} : ${byteLength(content)} octets (contenu : ${includes})`,
  );
}

function byteLength(content: unknown): number {
  if (content == null) {
    return 0;
  }
  if (content instanceof Uint8Array) {
    return content.byteLength;
  }
  const str = typeof content === "string" ? content : JSON.stringify(content);
  return new TextEncoder().encode(str).length;
}
