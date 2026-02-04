'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://api:8000';

type JobStatus = {
  job_id: string;
  status: string;
  progress: string;
  created_at: string;
  updated_at: string;
  error_message?: string | null;
  scan_id?: number | null;
};

type Summary = {
  target: string;
  total_findings: number;
  severity_counts: Record<string, number>;
};

export default function JobPage() {
  const params = useParams<{ id: string }>();
  const jobId = params?.id as string;
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [logs, setLogs] = useState<string>('');

  useEffect(() => {
    let timer: NodeJS.Timeout;

    async function fetchStatus() {
      const response = await fetch(`${API_BASE}/v1/jobs/${jobId}`);
      if (response.ok) {
        const payload = (await response.json()) as JobStatus;
        setStatus(payload);
        if (payload.status === 'complete') {
          fetchSummary();
          fetchLogs();
        }
      }
    }

    async function fetchSummary() {
      const response = await fetch(`${API_BASE}/v1/jobs/${jobId}/summary`);
      if (response.ok) {
        setSummary(await response.json());
      }
    }

    async function fetchLogs() {
      const response = await fetch(`${API_BASE}/v1/jobs/${jobId}/logs`);
      if (response.ok) {
        setLogs(await response.text());
      }
    }

    fetchStatus();
    timer = setInterval(fetchStatus, 3000);
    return () => clearInterval(timer);
  }, [jobId]);

  const progressSteps = [
    'uploaded',
    'validating',
    'extracting',
    'decompiling',
    'analyzing',
    'packaging',
    'complete'
  ];

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-50 via-slate-50 to-indigo-50 px-6 py-12 dark:from-slate-950 dark:via-slate-950 dark:to-indigo-950">
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
        <header className="flex flex-col gap-2">
          <a href="/" className="text-sm font-semibold text-indigo-600 hover:text-indigo-500">
            ← Back to upload
          </a>
          <h1 className="text-3xl font-semibold">Job {jobId}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Status: {status?.status ?? 'loading'} • Progress: {status?.progress ?? 'pending'}
          </p>
          {status?.scan_id && (
            <a
              href={`${API_BASE}/dashboard/scans/${status.scan_id}`}
              className="text-sm font-semibold text-indigo-600 hover:text-indigo-500"
            >
              View scan dashboard →
            </a>
          )}
        </header>

        <Card className="flex flex-col gap-4">
          <h2 className="text-lg font-semibold">Progress</h2>
          <div className="grid gap-3 md:grid-cols-4">
            {progressSteps.map((step) => {
              const active = status?.progress === step || status?.status === step;
              return (
                <div
                  key={step}
                  className={`rounded-xl border px-4 py-3 text-sm font-medium ${
                    active
                      ? 'border-indigo-500 bg-indigo-500/10 text-indigo-600 dark:text-indigo-300'
                      : 'border-slate-200 text-slate-500 dark:border-slate-800 dark:text-slate-400'
                  }`}
                >
                  {step}
                </div>
              );
            })}
          </div>
          {status?.error_message && (
            <p className="text-sm text-red-500">{status.error_message}</p>
          )}
        </Card>

        <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
          <Card className="flex flex-col gap-4">
            <h2 className="text-lg font-semibold">Summary</h2>
            {summary ? (
              <div className="grid gap-3">
                <div className="rounded-xl bg-slate-100 p-4 text-sm text-slate-700 dark:bg-slate-800 dark:text-slate-100">
                  <p>Target: {summary.target || 'Upload'}</p>
                  <p>Total findings: {summary.total_findings}</p>
                </div>
                <div className="grid gap-2 md:grid-cols-2">
                  {Object.entries(summary.severity_counts).map(([severity, count]) => (
                    <div
                      key={severity}
                      className="rounded-xl border border-slate-200 px-4 py-3 text-sm text-slate-600 dark:border-slate-800 dark:text-slate-200"
                    >
                      <span className="font-semibold">{severity}</span>: {count}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-sm text-slate-500">Summary will appear once the job completes.</p>
            )}
          </Card>

          <Card className="flex flex-col gap-4">
            <h2 className="text-lg font-semibold">Download</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Download the full report directory as a ZIP once the job is complete.
            </p>
            <Button
              variant="secondary"
              disabled={status?.status !== 'complete'}
              onClick={() => {
                window.location.href = `${API_BASE}/v1/jobs/${jobId}/report.zip`;
              }}
            >
              Download report
            </Button>
          </Card>
        </div>

        <Card className="flex flex-col gap-4">
          <h2 className="text-lg font-semibold">Logs</h2>
          <pre className="max-h-64 overflow-auto rounded-xl bg-slate-950 p-4 text-xs text-slate-100">
            {logs || 'Logs will appear when available.'}
          </pre>
        </Card>
      </div>
    </main>
  );
}
