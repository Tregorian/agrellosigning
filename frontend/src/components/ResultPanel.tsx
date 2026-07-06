import { useMemo, useState } from "react";
import { verifyFile, base64ToBlob, type SignResponse, type VerifyResponse } from "../api";

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="row">
      <span className="label">{label}</span>
      <span className="value">{value}</span>
    </div>
  );
}

export function ResultPanel({ result, originalFile }: { result: SignResponse; originalFile: File }) {
  const [verification, setVerification] = useState<VerifyResponse | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const signatureBlob = useMemo(() => base64ToBlob(result.signatureBase64), [result.signatureBase64]);

  const download = () => {
    const url = URL.createObjectURL(signatureBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${result.fileName}.p7s`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  const runVerify = async () => {
    setVerifyError(null);
    setVerification(null);
    setVerifying(true);
    try {
      setVerification(await verifyFile(originalFile, signatureBlob));
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : "Verification failed");
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="panel">
      <h2>Signature created</h2>
      <Row label="File" value={result.fileName} />
      <Row label="SHA-256" value={result.sha256Hex} />
      <Row label="Signer" value={result.signerSubject} />
      <Row label="Signed at" value={result.signingTime} />
      <Row label="Algorithm" value={result.signatureAlgorithm} />
      <Row label="Format" value={result.signatureFormat} />

      <div className="actions">
        <button onClick={download}>Download .p7s</button>
        <button className="secondary" onClick={runVerify} disabled={verifying}>
          {verifying ? "Verifying…" : "Verify this signature"}
        </button>
      </div>

      {verifyError && <div className="error">{verifyError}</div>}

      {verification && (
        <div style={{ marginTop: 16 }}>
          <span className={`badge ${verification.valid ? "ok" : "bad"}`}>
            {verification.valid ? "✓ Signature valid" : "✗ Invalid"}
          </span>
          {verification.reason && <div className="error">{verification.reason}</div>}
        </div>
      )}

      <p className="subtitle" style={{ marginTop: 24 }}>Verify it yourself with OpenSSL:</p>
      <code className="block">{`# save the downloaded .p7s next to your original file, then:
curl -s ${window.location.origin}/api/certificate > cert.pem
openssl cms -verify -binary -content "${result.fileName}" \\
  -in "${result.fileName}.p7s" -inform DER \\
  -CAfile cert.pem -noverify`}</code>
    </div>
  );
}
