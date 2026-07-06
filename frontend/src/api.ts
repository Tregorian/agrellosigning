export interface SignResponse {
  fileName: string;
  sha256Hex: string;
  signerSubject: string;
  signingTime: string;
  signatureAlgorithm: string;
  signatureFormat: string;
  signatureBase64: string;
}

export interface VerifyResponse {
  valid: boolean;
  signerSubject?: string;
  signingTime?: string;
  signatureAlgorithm?: string;
  reason?: string;
}

export async function signFile(file: File): Promise<SignResponse> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch("/api/sign", { method: "POST", body: form });
  if (!res.ok) {
    const msg = await res.json().then((j) => j.error).catch(() => null);
    throw new Error(msg ?? `Signing failed (HTTP ${res.status})`);
  }
  return res.json();
}

export async function verifyFile(file: File, signature: Blob): Promise<VerifyResponse> {
  const form = new FormData();
  form.append("file", file);
  form.append("signature", signature, "signature.p7s");
  const res = await fetch("/api/verify", { method: "POST", body: form });
  if (!res.ok) {
    const msg = await res.json().then((j) => j.error).catch(() => null);
    throw new Error(msg ?? `Verification failed (HTTP ${res.status})`);
  }
  return res.json();
}

export function base64ToBlob(b64: string): Blob {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return new Blob([bytes], { type: "application/pkcs7-signature" });
}
