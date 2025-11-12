"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import api from "../lib/api";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { ShieldAlert, ShieldCheck, ShieldHalf, FileText, RefreshCcw, Moon, Sun } from "lucide-react";
import { cn } from "../lib/utils";
import { useTheme } from "next-themes";

const schema = z.object({
  accessKeyId: z.string().min(16, "Access Key ID required"),
  secretAccessKey: z.string().min(32, "Secret Access Key required"),
  regionScope: z.string().optional(),
  roleArn: z.string().optional(),
  externalId: z.string().optional()
});

const regionOptions = [
  { label: "All Regions", value: "all" },
  { label: "us-east-1", value: "us-east-1" },
  { label: "us-west-2", value: "us-west-2" }
];

type FormValues = z.infer<typeof schema>;

type Finding = {
  id: string;
  ruleId: string;
  service: string;
  severity: string;
  status: string;
  evidence: Record<string, unknown>;
  region?: string;
};

type Summary = {
  severityTotals: Record<string, number>;
  serviceTotals: Record<string, number>;
  totalFindings: number;
  status: string;
};

const severityColors: Record<string, string> = {
  CRITICAL: "bg-rose-500",
  HIGH: "bg-amber-500",
  MEDIUM: "bg-sky-500",
  LOW: "bg-emerald-500"
};

export default function Page() {
  const { register, handleSubmit, formState, setValue } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { regionScope: "all" }
  });
  const [scanId, setScanId] = useState<string | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const { theme, setTheme } = useTheme();

  const onSubmit = useCallback(
    async (values: FormValues) => {
      setLoading(true);
      try {
        const payload = { ...values, regionScope: values.regionScope === "all" ? "all" : [values.regionScope] };
        const response = await api.post("/api/scans/start", payload);
        const id = response.data.scanId;
        setScanId(id);
      } catch (error) {
        console.error("Failed to start scan", error);
      } finally {
        setLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    if (!scanId) return;
    const interval = setInterval(async () => {
      try {
        const statusResponse = await api.get(`/api/scans/${scanId}/summary`);
        setSummary(statusResponse.data);
        const findingsResponse = await api.get(`/api/scans/${scanId}/findings`);
        setFindings(findingsResponse.data.items ?? []);
      } catch (error) {
        console.error("Failed to fetch scan results", error);
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [scanId]);

  const heatmap = useMemo(() => {
    if (!summary) return [] as Array<{ severity: string; count: number }>;
    return Object.entries(summary.severityTotals || {}).map(([severity, count]) => ({ severity, count }));
  }, [summary]);

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 text-slate-100">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-semibold">AWS SecureScope</h1>
          <p className="text-sm text-slate-400">
            Agentless AWS security posture management with opinionated EC2 and EKS checks.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
            {theme === "dark" ? (
              <Sun className="h-4 w-4" aria-hidden />
            ) : (
              <Moon className="h-4 w-4" aria-hidden />
            )}
            <span className="sr-only">Toggle theme</span>
          </Button>
          <Button variant="outline" asChild>
            <a href="/api/docs" target="_blank" rel="noreferrer">
              API docs
            </a>
          </Button>
        </div>
      </header>

      <section className="mt-6 grid gap-6 lg:grid-cols-[400px_1fr]">
        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-6 shadow-lg">
          <h2 className="text-lg font-semibold">Start a new scan</h2>
          <p className="mt-1 text-sm text-slate-400">
            Credentials are only held in memory for this session and never persisted.
          </p>
          <form className="mt-4 space-y-4" onSubmit={handleSubmit(onSubmit)}>
            <label className="block text-sm font-medium" htmlFor="accessKeyId">
              Access Key ID
            </label>
            <Input id="accessKeyId" autoComplete="off" {...register("accessKeyId")} aria-invalid={!!formState.errors.accessKeyId} />
            {formState.errors.accessKeyId && (
              <p className="text-sm text-rose-400">{formState.errors.accessKeyId.message}</p>
            )}

            <label className="block text-sm font-medium" htmlFor="secretAccessKey">
              Secret Access Key
            </label>
            <Input
              id="secretAccessKey"
              type="password"
              autoComplete="off"
              {...register("secretAccessKey")}
              aria-invalid={!!formState.errors.secretAccessKey}
            />
            {formState.errors.secretAccessKey && (
              <p className="text-sm text-rose-400">{formState.errors.secretAccessKey.message}</p>
            )}

            <label className="block text-sm font-medium">Region Scope</label>
            <Select
              defaultValue="all"
              onValueChange={(value) => setValue("regionScope", value)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select regions" />
              </SelectTrigger>
              <SelectContent>
                {regionOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <label className="block text-sm font-medium" htmlFor="roleArn">
              Optional Role ARN
            </label>
            <Input id="roleArn" placeholder="arn:aws:iam::123456789012:role/ReadOnly" {...register("roleArn")} />

            <label className="block text-sm font-medium" htmlFor="externalId">
              External ID (if using AssumeRole)
            </label>
            <Input id="externalId" placeholder="customer-external-id" {...register("externalId")} />

            <Button className="w-full" type="submit" disabled={loading}>
              {loading ? <RefreshCcw className="mr-2 h-4 w-4 animate-spin" aria-hidden /> : null}
              Launch scan
            </Button>
          </form>
          <p className="mt-4 text-xs text-slate-500">
            SecureScope validates credentials with STS, shards scans per region, and never stores secrets at rest.
          </p>
        </div>

        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4">
              <div className="flex items-center gap-3">
                <ShieldAlert className="h-5 w-5 text-rose-400" aria-hidden />
                <div>
                  <p className="text-xs uppercase text-slate-500">Critical Findings</p>
                  <p className="text-2xl font-semibold">
                    {summary?.severityTotals?.CRITICAL ?? 0}
                  </p>
                </div>
              </div>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4">
              <div className="flex items-center gap-3">
                <ShieldHalf className="h-5 w-5 text-amber-400" aria-hidden />
                <div>
                  <p className="text-xs uppercase text-slate-500">High & Medium</p>
                  <p className="text-2xl font-semibold">
                    {(summary?.severityTotals?.HIGH ?? 0) + (summary?.severityTotals?.MEDIUM ?? 0)}
                  </p>
                </div>
              </div>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4">
              <div className="flex items-center gap-3">
                <ShieldCheck className="h-5 w-5 text-emerald-400" aria-hidden />
                <div>
                  <p className="text-xs uppercase text-slate-500">Total Findings</p>
                  <p className="text-2xl font-semibold">{summary?.totalFindings ?? 0}</p>
                </div>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Severity heatmap</h2>
              <div className="flex gap-2">
                {heatmap.map((item) => (
                  <span
                    key={item.severity}
                    className={cn(
                      "flex items-center gap-2 rounded-full px-3 py-1 text-xs",
                      severityColors[item.severity] ?? "bg-slate-700"
                    )}
                  >
                    {item.severity}
                    <span className="font-semibold">{item.count}</span>
                  </span>
                ))}
              </div>
            </div>
            {!heatmap.length && (
              <p className="mt-6 text-sm text-slate-400">
                No findings yet. Run a scan to populate the heatmap.
              </p>
            )}
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Findings</h2>
              {scanId && (
                <Button variant="outline" asChild>
                  <a href={`/api/scans/${scanId}/export.md`} target="_blank" rel="noreferrer">
                    <FileText className="mr-2 h-4 w-4" aria-hidden /> Export Markdown
                  </a>
                </Button>
              )}
            </div>
            <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800">
              <table className="min-w-full divide-y divide-slate-800">
                <thead className="bg-slate-900/80">
                  <tr>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Severity
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Rule
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Service
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Region
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Evidence
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {findings.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-4 py-6 text-center text-sm text-slate-500">
                        Findings will appear here once the scan completes.
                      </td>
                    </tr>
                  )}
                  {findings.map((finding) => (
                    <tr key={finding.id} className="hover:bg-slate-900/60">
                      <td className="px-4 py-3">
                        <span
                          className={cn(
                            "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold",
                            severityColors[finding.severity] ?? "bg-slate-700"
                          )}
                        >
                          {finding.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm font-semibold">{finding.ruleId}</td>
                      <td className="px-4 py-3 text-sm text-slate-300">{finding.service}</td>
                      <td className="px-4 py-3 text-sm text-slate-300">{finding.region ?? "-"}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        <pre className="max-w-xs whitespace-pre-wrap break-words">
                          {JSON.stringify(finding.evidence, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
