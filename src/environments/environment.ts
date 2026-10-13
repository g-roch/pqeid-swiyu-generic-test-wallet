export const environment = {
    trustApiBaseUrl: 'https://trust-data-service-int-a.apps.p-szb-ros-shrd-npr-01.cloud.admin.ch',
    allowedHosts: new Set([
        'trust-data-service-int-a.apps.p-szb-ros-shrd-npr-01.cloud.admin.ch',
    ]),
    trustRoot: "did:webvh:QmQNMXCBYHLsH5zJeE1hC6tn7GpQFfvqJaWPqwpn7pafcy:identifier-reg-a.trust-infra.swiyu-int.admin.ch:api:v1:did:3d20b010-8d39-4cdd-b5cd-a6356b4e1218",
    // PQEID: JWS algorithms the wallet accepts from issuers/verifiers (policy). Expand phase:
    // ML-DSA-44 + composite; contract = drop ML-DSA-44. Classical ES256 is refused.
    acceptedSignatureAlgorithms: ['ML-DSA-44', 'ML-DSA-65-ES256'] as readonly string[],
};