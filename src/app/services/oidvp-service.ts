import { HttpClient, HttpHeaders, HttpParams } from "@angular/common/http";
import { inject, Injectable } from "@angular/core";
import { from, map, Observable, of, switchMap, tap } from "rxjs";
import { VpTokenMap } from "@app/models/api-response";
import { RequestObject } from "src/generated/verifier";
import { encryptJwe } from "@app/crypto/jwe";
import { logMessageSize } from "./message-size-logger";

@Injectable({
  providedIn: "root",
})
export class OIDVPService {
  private http = inject(HttpClient);

  fetchRequestObject(requestObjectUrl: string): Observable<RequestObject | string> {
    if (!requestObjectUrl) {
      throw new Error("requestObjectUrl is required");
    }

    return this.http.get(requestObjectUrl, { responseType: "text" }).pipe(
      tap((response: string) =>
        logMessageSize(
          "Vérification",
          "Request Object (réponse)",
          "JWT signé complet (dcql_query, nonce, client_metadata incl.)",
          response,
        ),
      ),
      map((response: string) => {
        try {
          return JSON.parse(response) as RequestObject;
        } catch {
          return response;
        }
      })
    );
  }

  submitVerificationResponse(
    requestObject: RequestObject,
    vpToken: string,
    credentialId = "credential_1"
  ): Observable<string> {
    if (!requestObject?.response_uri) {
      throw new Error("No response_uri provided in request object");
    }

    if (!vpToken?.trim()) {
      throw new Error("VP token is empty or undefined");
    }

    const vpTokenMap: VpTokenMap = {
      [credentialId]: [vpToken],
    };

    return this.preparePayload(requestObject, JSON.stringify(vpTokenMap)).pipe(
      switchMap(({ body, headers }) =>
        this.http.post(requestObject.response_uri!, body.toString(), {
          headers,
          responseType: "text",
        })
      )
    );
  }

  private preparePayload(
    requestObject: RequestObject,
    vpTokenJson: string
  ): Observable<{ body: HttpParams; headers: HttpHeaders }> {
    const headers = new HttpHeaders({
      "Content-Type": "application/x-www-form-urlencoded",
      "SWIYU-API-Version": "2",
    });

    // The verifier echoes `state` back for request/response correlation and rejects the
    // submission otherwise ("OAuth2.0 State mismatch") - see
    // VerificationPresentationUnionDto.state in swiyu-verifier.
    const withState = (body: HttpParams): HttpParams =>
      requestObject.state ? body.set("state", requestObject.state) : body;

    if (requestObject.response_mode === "direct_post.jwt") {
      return from(this.encryptVerifierPayload(requestObject, vpTokenJson)).pipe(
        tap((encryptedPayload: string) =>
          logMessageSize(
            "Vérification",
            "Réponse de présentation envoyée (\"response\")",
            "JWE compact (VP token + key-binding JWT chiffrés pour le verifier)",
            encryptedPayload,
          ),
        ),
        map((encryptedPayload: string) => ({
          body: withState(new HttpParams().set("response", encryptedPayload)),
          headers,
        }))
      );
    }

    logMessageSize(
      "Vérification",
      "Réponse de présentation envoyée (\"vp_token\")",
      "VP token en clair (non chiffré - response_mode != direct_post.jwt)",
      vpTokenJson,
    );

    return of({
      body: withState(new HttpParams().set("vp_token", vpTokenJson)),
      headers,
    });
  }

  private async encryptVerifierPayload(
    requestObject: RequestObject,
    vpTokenJson: string
  ): Promise<string> {
    const encryptionKey = requestObject.client_metadata?.jwks?.keys?.[0];

    if (!encryptionKey) {
      throw new Error("No encryption key available in client_metadata.jwks.keys");
    }

    if (!encryptionKey.alg || !encryptionKey.kty) {
      throw new Error("Invalid JWK: missing alg or kty properties");
    }

    const encryptionEnc = requestObject.client_metadata?.encrypted_response_enc_values_supported?.[0];
    if (!encryptionEnc) {
      throw new Error("No encryption algorithm specified in encrypted_response_enc_values_supported");
    }

    let vpToken: unknown;
    try {
      vpToken = JSON.parse(vpTokenJson);
    } catch (error) {
      throw new Error(`Invalid vp_token JSON format: ${(error as Error).message}`);
    }

    // JWE encryption of the verification response for the verifier's advertised key, alg
    // taken dynamically from request_object.client_metadata (now "XWING" after the
    // verifier's PQC migration, see ManagementService.createEncryptionKeys in
    // swiyu-verifier) - dispatches to X-Wing (jwe.ts) or classical `jose` accordingly.
    return encryptJwe(
      { vp_token: vpToken },
      encryptionKey as any,
      encryptionKey.alg,
      encryptionEnc,
    );
  }
}
