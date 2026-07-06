import { useRef, useState } from "react";
import { signFile, type SignResponse } from "./api";
import { ResultPanel } from "./components/ResultPanel";

export function App() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<SignResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const choose = (f: File | null) => {
    setFile(f);
    setResult(null);
    setError(null);
  };

  const sign = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    try {
      setResult(await signFile(file));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Signing failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>Agrello File Signing</h1>
      <p className="subtitle">Upload a file to produce a detached CMS/CAdES signature.</p>

      <div className="panel">
        <div
          className={`dropzone ${drag ? "drag" : ""}`}
          onClick={() => inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); choose(e.dataTransfer.files[0] ?? null); }}
        >
          {file ? <strong>{file.name}</strong> : "Drop a file here or click to choose"}
          <input
            ref={inputRef}
            type="file"
            style={{ display: "none" }}
            onChange={(e) => choose(e.target.files?.[0] ?? null)}
          />
        </div>
        <div className="actions">
          <button onClick={sign} disabled={!file || loading}>
            {loading ? "Signing…" : "Sign file"}
          </button>
        </div>
        {error && <div className="error">{error}</div>}
      </div>

      {result && file && <ResultPanel result={result} originalFile={file} />}
    </div>
  );
}
