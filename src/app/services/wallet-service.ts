import { inject, Injectable, signal, WritableSignal } from "@angular/core";
import { HolderKeyService } from "./holder-key.service";
import { CryptoService } from "./crypto-service";
import {
  JwtPayload,
  OpenIdMetadataResponse,
  RegistryEntry,
} from "@app/models/api-response";
import * as jose from "jose";
import {
  CreateCredentialRequest,
  CredentialConfiguration,
  CredentialEndpointResponse,
  NonceResponse,
} from "src/generated/issuer";
import { WalletOptions } from "@app/models/wallet-options";
import { VCRecord } from "@app/models/vc-record";
import { VcKeyStoreService } from "./vc-key-store.service";
import { generateHolderKeyPair, HolderKeyPair } from "@app/crypto/holder-key";
import { signJwtWithHolderKey, verifyJwtWithJwk } from "@app/crypto/jwt";
import { EphemeralKeyPair } from "@app/crypto/jwe";

interface ProofKeyPair {
  proofIndex: number;
  keyPair: HolderKeyPair;
}

@Injectable({
  providedIn: "root",
})
export class WalletService {
  private holderKeyService = inject(HolderKeyService);
  private cryptoService = inject(CryptoService);
  private vcKeyStore = inject(VcKeyStoreService);
  private requestedVCs: WritableSignal<VCRecord[]> = signal([]);

  private readonly STORAGE_KEY = "wallet_options";
  private readonly defaultOptions: WalletOptions = {
    payloadEncryptionPreference: true,
    numberOfProofs: false,
    useSignedMetadata: true,
    useDPoP: true,
    useProtectedIssuance: false,
  };

  private walletOptions: WritableSignal<WalletOptions> = signal(
    this.loadOptions(),
  );

  constructor() {
    this.initializeOptions();
  }

  private loadOptions(): WalletOptions {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      if (stored) {
        return JSON.parse(stored) as WalletOptions;
      }
    } catch (error) {
      console.error("Failed to load wallet options from localStorage", error);
    }
    return this.defaultOptions;
  }

  private saveOptions(): void {
    try {
      localStorage.setItem(
        this.STORAGE_KEY,
        JSON.stringify(this.walletOptions()),
      );
    } catch (error) {
      console.error("Failed to save wallet options to localStorage", error);
    }
  }

  private initializeOptions(): void {
    this.walletOptions.set(this.loadOptions());
  }

  getOptions(): WalletOptions {
    return this.walletOptions();
  }

  getOptionsSignal(): WritableSignal<WalletOptions> {
    return this.walletOptions;
  }

  updatePayloadEncryptionPreference(value: boolean): void {
    this.walletOptions.update((options: WalletOptions) => ({
      ...options,
      payloadEncryptionPreference: value,
    }));
    this.saveOptions();
  }

  updateNumberOfProofs(value: false | number): void {
    this.walletOptions.update((options: WalletOptions) => ({
      ...options,
      numberOfProofs: value,
    }));
    this.saveOptions();
  }

  updateUseDpop(value: boolean): void {
    this.walletOptions.update((options: WalletOptions) => ({
      ...options,
      useDPoP: value,
    }));
    this.saveOptions();
  }

  updateUseSignedMetadata(value: boolean): void {
    this.walletOptions.update((options: WalletOptions) => ({
      ...options,
      useSignedMetadata: value,
    }));
    this.saveOptions();
  }

  updateUseProtectedIssuance(value: boolean): void {
    this.walletOptions.update((options: WalletOptions) => ({
      ...options,
      useProtectedIssuance: value,
    }));
    this.saveOptions();
  }

  resetToDefaults(): void {
    this.walletOptions.set(this.defaultOptions);
    this.saveOptions();
  }

  private ephemeralKeyPair?: EphemeralKeyPair;
  private generatedProofKeyPairs: ProofKeyPair[] = [];

  setEphemeralKeyPair(keyPair: EphemeralKeyPair) {
    this.ephemeralKeyPair = keyPair;
  }

  getEphemeralKeyPair(): EphemeralKeyPair | undefined {
    return this.ephemeralKeyPair;
  }

  private getCredentialConfig(
    metadata: OpenIdMetadataResponse,
    configId: string,
  ) {
    const entries = Object.entries(
      metadata.credential_configurations_supported ?? {},
    );

    if (!entries.length) {
      throw new Error("No credential configurations available");
    }

    const [credentialConfigurationId, credentialConfiguration] =
      entries.find(([id]) => id === configId) ?? entries[0];

    return {
      credentialConfigurationId: credentialConfigurationId as string,
      credentialConfiguration:
        credentialConfiguration as CredentialConfiguration,
    };
  }

  buildRegistryUrl(credential: string): string {
    if (!credential) {
      throw new Error("Missing credential in credential response");
    }
    const token = credential.split("~")[0];
    if (!token) {
      throw new Error("Missing token");
    }
    const decoded = jose.decodeJwt(token) as JwtPayload;
    const did = decoded["iss"] as string;
    if (!did) {
      throw new Error("Cannot find the iss");
    }
    const parts = did.split(":");
    return `https://${decodeURIComponent(did.substring(did.indexOf(parts[3]), did.length).replace(/:/g, "/"))}/did.jsonl`;
  }

  public async decodeJwt(
    jwt: string,
    registryEntry: Record<string, unknown>,
  ): Promise<{ payload: JwtPayload; protectedHeader: JwtPayload }> {
    const kid = (jose.decodeProtectedHeader(jwt) as JwtPayload)["kid"];
    const verificationMethods = (registryEntry[
      "state"
    ] as any);

    console.log("Decoding JWT with registry entry", { jwt, kid, verificationMethods });
    const verificationMethod = (
      (verificationMethods?.["verificationMethod"] as Record<
        string,
        unknown
      >[]) || []
    )
      .map((meth) =>
        (meth as Record<string, unknown>)["id"] === kid ? meth : null,
      )
      .filter(
        (
          meth: Record<string, unknown> | null,
        ): meth is Record<string, unknown> => meth != null,
      )[0];
    const jwk = verificationMethod?.["publicKeyJwk"];
    // Verifies the issued credential's signature against the DID-registry public key -
    // dispatches to ML-DSA (mldsa.ts) or classical `jose` based on jwk.kty, see
    // crypto/jwt.ts::verifyJwtWithJwk.
    const { payload, protectedHeader } = await verifyJwtWithJwk(jwt, jwk as any);
    return {
      payload: payload as JwtPayload,
      protectedHeader: protectedHeader as JwtPayload,
    };
  }

  public async decodeJwtWithListRegistry(
    jwt: string,
    registryEntry: RegistryEntry[],
  ): Promise<{ payload: JwtPayload; protectedHeader: JwtPayload }> {
    const kid = (jose.decodeProtectedHeader(jwt) as JwtPayload)["kid"];
    const verificationMethods = (registryEntry[3] as Record<string, unknown>)?.[
      "value"
    ] as Record<string, unknown>;
    const verificationMethod = (
      (verificationMethods?.["verificationMethod"] as Record<
        string,
        unknown
      >[]) || []
    )
      .map((meth) =>
        (meth as Record<string, unknown>)["id"] === kid ? meth : null,
      )
      .filter(
        (
          meth: Record<string, unknown> | null,
        ): meth is Record<string, unknown> => meth != null,
      )[0];
    const jwk = verificationMethod?.["publicKeyJwk"];
    // Same alg-aware dispatch as decodeJwt above (this variant handles the list-shaped
    // registryEntry response format).
    const { payload, protectedHeader } = await verifyJwtWithJwk(jwt, jwk as any);
    return {
      payload: payload as JwtPayload,
      protectedHeader: protectedHeader as JwtPayload,
    };
  }

  async buildRequestCredential(
    metadata: OpenIdMetadataResponse,
    nonce: NonceResponse,
    configId: string,
    proofsSizePreference: number | null = null,
    encryptionPreference = false,
  ): Promise<CreateCredentialRequest | string> {
    console.log("metadata", metadata);

    const buildEncrypted =
      metadata.credential_request_encryption?.encryption_required ||
      encryptionPreference;

    const numberOfProofs =
      proofsSizePreference ??
      metadata.batch_credential_issuance?.batch_size ??
      1;

    const credentialIssuer = metadata.credential_issuer as string;

    if (!credentialIssuer) {
      throw new Error("No credentialIssuer available");
    }

    const { credentialConfigurationId, credentialConfiguration } =
      this.getCredentialConfig(metadata, configId);

    const format = credentialConfiguration?.["format"] as string;

    if (!format) {
      throw new Error("No format available");
    }

    const proofAlg =
      credentialConfiguration?.proof_types_supported?.["jwt"]
        .proof_signing_alg_values_supported?.[0];

    if (!proofAlg) {
      throw new Error("No proof signing algorithm available");
    }

    const proofs = {
      proof_type: "jwt",
      jwt: [] as string[],
    };

    this.generatedProofKeyPairs = [];

    for (let i = 0; i < numberOfProofs; i++) {
      // Holder-binding proof key pair, generated for whatever `proofAlg` the issuer actually
      // advertised (ML-DSA via mldsa.ts, classical EC via WebCrypto otherwise - see
      // crypto/holder-key.ts::generateHolderKeyPair). This key is later reused as the
      // per-VC key-binding key in credential-issuance.ts, so its type must match what the
      // verifier will require at presentation time too.
      const keyPair = await generateHolderKeyPair(proofAlg);

      this.generatedProofKeyPairs.push({
        proofIndex: i,
        keyPair,
      });

      const jwt = await this.buildHolderBindingWithKey(
        Math.floor(Date.now() / 1000),
        credentialIssuer,
        nonce.c_nonce,
        keyPair,
      );
      proofs.jwt.push(jwt);
    }

    const payload: CreateCredentialRequest = {
      format,
      credential_configuration_id: credentialConfigurationId,
      proofs,
    };

    // Ephemeral JWE key pair the issuer will encrypt its response with, generated for
    // whatever alg the issuer's credential_response_encryption actually advertises (XWING
    // via jwe.ts, classical ECDH-ES via `jose` otherwise), instead of a hardcoded "ECDH-ES".
    const responseEncAlg =
      metadata.credential_response_encryption?.alg_values_supported?.[0] ??
      "ECDH-ES";
    const ephemeralKeyPair =
      await this.cryptoService.generateEphemeralKeyPair(responseEncAlg);
    this.setEphemeralKeyPair(ephemeralKeyPair);
    const publicJwk = await this.cryptoService.exportPublicJwk(
      ephemeralKeyPair,
    );

    if (buildEncrypted) {
      const encConfig = metadata.credential_response_encryption;

      if (encConfig?.alg_values_supported?.length) {
        const alg = encConfig.alg_values_supported[0];
        const enc = encConfig.enc_values_supported?.[0];

        payload.credential_response_encryption = {
          alg,
          enc,
          jwk: publicJwk,
        };
      }

      const requestEnc = metadata.credential_request_encryption;
      const jwk = requestEnc?.jwks?.keys?.[0];
      const alg = jwk?.alg ? jwk?.alg : encConfig.alg_values_supported[0];
      const enc = requestEnc?.enc_values_supported?.[0];
      const zip = requestEnc?.zip_values_supported?.[0];

      if (!jwk) {
        throw new Error(
          "No encryption key available in credential_request_encryption.jwks.keys",
        );
      }
      if (!alg) {
        throw new Error(
          "No alg available in credential_request_encryption.jwks.keys",
        );
      }
      if (!enc) {
        throw new Error(
          "No encryption value available in credential_request_encryption.enc_values_supported",
        );
      }
      if (!zip) {
        throw new Error(
          "No encryption value available in credential_request_encryption.zip_values_supported",
        );
      }

      return this.cryptoService.encryptPayload(payload, jwk, alg, enc, zip);
    }

    return payload;
  }

  // Note: this method does not appear to be called anywhere in src/ (buildHolderBindingWithKey
  // below is used instead) - dead code, kept for parity with the holder-key-service fallback.
  async buildHolderBinding(
    now: number,
    audience: string,
    nonce: string,
  ): Promise<string> {
    return signJwtWithHolderKey(
      this.holderKeyService.getKeyPair(),
      { nonce },
      { typ: "openid4vci-proof+jwt", jwk: this.holderKeyService.getJwk() },
      { audience, expiresIn: "2h", issuedAt: now },
    );
  }

  async buildHolderBindingWithKey(
    now: number,
    audience: string,
    nonce: string,
    keyPair: HolderKeyPair,
  ): Promise<string> {
    return signJwtWithHolderKey(
      keyPair,
      { nonce },
      { typ: "openid4vci-proof+jwt", jwk: keyPair.jwk },
      { audience, expiresIn: "2h", issuedAt: now },
    );
  }

  getGeneratedProofKeyPairs(): ProofKeyPair[] {
    return this.generatedProofKeyPairs;
  }

  async resolveResponseCredential(
    encryptedResponse: CredentialEndpointResponse | string,
  ) {
    const keyPair = this.getEphemeralKeyPair();

    if (!keyPair) {
      throw new Error("Missing wallet ephemeral key pair");
    }

    return this.cryptoService.decryptPayload(
      encryptedResponse,
      keyPair,
    ) as CredentialEndpointResponse;
  }

  getRequestedVCs(): WritableSignal<VCRecord[]> {
    return this.requestedVCs;
  }

  addVC(credentialType: string, sdJwt: string): void {
    const newVC: VCRecord = {
      id: `vc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      credentialType,
      issuedAt: new Date(),
      sdJwt,
    };

    this.requestedVCs.update((vcs) => [...vcs, newVC]);
  }

  removeVC(id: string): void {
    this.requestedVCs.update((vcs) => vcs.filter((vc) => vc.id !== id));
  }

  clearAll(): void {
    this.requestedVCs.set([]);
  }

  getVCCount(): number {
    return this.requestedVCs().length;
  }
}
