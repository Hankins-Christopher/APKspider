'use client';

import { useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

export default function HomePage() {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);

  const accepted = useMemo(() => ['.apk', '.xapk'], []);

  async function handleUpload() {
    if (!file) return;
    setIsUploading(true);
    setError(null);
    try {
      const form = new FormData();
      form.append('file', file);
      const response = await fetch(`${API_BASE}/v1/jobs`, {
        method: 'POST',
        body: form
      });
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.detail || 'Upload failed');
      }
      const payload = await response.json();
      setJobId(payload.job_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setIsUploading(false);
    }
  }

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-50 via-slate-50 to-indigo-50 px-6 py-12 dark:from-slate-950 dark:via-slate-950 dark:to-indigo-950">
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-8">
        <header className="flex flex-col gap-3">
          <span className="text-sm uppercase tracking-[0.3em] text-indigo-500">APKspider</span>
          <h1 className="text-4xl font-semibold leading-tight text-slate-900 dark:text-white">
            Secure APK/XAPK analysis, ready when you are.
          </h1>
          <p className="max-w-2xl text-base text-slate-600 dark:text-slate-300">
            Upload an APK or XAPK to run APKspider’s hardened analysis pipeline. Files are validated, sandboxed,
            and processed with strict resource limits.
          </p>
        </header>

        <Card className="flex flex-col gap-6">
          <div className="flex flex-col gap-2">
            <h2 className="text-xl font-semibold">Upload file</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Accepted formats: {accepted.join(', ')} • Max size 250MB • No URLs or package downloads
            </p>
          </div>

          <div className="flex flex-col gap-4 rounded-xl border border-dashed border-slate-300 p-6 text-center dark:border-slate-700">
            <input
              type="file"
              accept={accepted.join(',')}
              onChange={(event) => {
                const selected = event.target.files?.[0];
                setFile(selected ?? null);
                setJobId(null);
              }}
              className="block w-full text-sm text-slate-600 file:mr-4 file:rounded-md file:border-0 file:bg-slate-200 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-slate-700 hover:file:bg-slate-300 dark:text-slate-300 dark:file:bg-slate-800 dark:file:text-slate-100 dark:hover:file:bg-slate-700"
            />
            {file ? (
              <p className="text-sm text-slate-500">Selected: {file.name}</p>
            ) : (
              <p className="text-sm text-slate-500">Choose an APK or XAPK to start the scan.</p>
            )}
          </div>

          {error && <p className="text-sm text-red-500">{error}</p>}

          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={handleUpload} disabled={!file || isUploading}>
              {isUploading ? 'Uploading…' : 'Start analysis'}
            </Button>
            {jobId && (
              <a
                href={`/jobs/${jobId}`}
                className="text-sm font-semibold text-indigo-600 hover:text-indigo-500"
              >
                View job status →
              </a>
            )}
          </div>
        </Card>

        <section className="grid gap-6 md:grid-cols-3">
          {[
            {
              title: 'Hardened uploads',
              description: 'Signature validation, strict limits, and unicode-safe file handling guard against hostile input.'
            },
            {
              title: 'Sandboxed execution',
              description: 'Jobs run with low privileges, resource caps, and optional network isolation.'
            },
            {
              title: 'Actionable output',
              description: 'Review summaries, inspect sanitized logs, and download the full report.'
            }
          ].map((item) => (
            <Card key={item.title} className="flex flex-col gap-2">
              <h3 className="text-lg font-semibold">{item.title}</h3>
              <p className="text-sm text-slate-500 dark:text-slate-400">{item.description}</p>
            </Card>
          ))}
        </section>
      </div>
    </main>
  );
}
