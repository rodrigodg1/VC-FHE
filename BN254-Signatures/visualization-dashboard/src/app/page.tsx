"use client";

import { useMetrics } from '@/hooks/useMetrics';
import { ExecutionTimeChart } from '@/components/Charts/ExecutionTimeChart';
import { StageDistributionChart } from '@/components/Charts/StageDistributionChart';
import { TimelineChart } from '@/components/Charts/TimelineChart';
import { GasUsageChart } from '@/components/Charts/GasUsageChart';
import { TransactionSizeChart } from '@/components/Charts/TransactionSizeChart';
import { ExecutionTimeDistributionChart } from '@/components/Charts/ExecutionTimeDistributionChart';
import { BlockchainStatus } from '@/components/BlockchainStatus';

import { ExperimentResult } from '@/types';

export default function Home() {
  const { data, summary, loading, error, lastUpdated } = useMetrics(3000);

  if (loading && data.length === 0) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen text-red-500">
        <p>{error}</p>
      </div>
    );
  }

  const latestRun = data[data.length - 1] as ExperimentResult | undefined;

  return (
    <div className="container min-h-screen py-8">
      <header className="header mb-8">
        <h1 className="text-4xl font-bold mb-2">Simulation Dashboard</h1>
        <p className="text-muted">Real-time Privacy-Preserving QoE Experiment Metrics</p>

        <div className="flex justify-between items-end mt-4">
          {lastUpdated && (
            <p className="text-xs text-gray-500 font-mono">Last updated: {new Date(lastUpdated).toLocaleTimeString()}</p>
          )}
          <div className="flex gap-2">
            <span className="px-3 py-1 bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300 rounded-full text-xs font-semibold">
              Status: Monitoring
            </span>
          </div>
        </div>
      </header>

      {/* Metric Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <MetricCard
          label="Total Experiments"
          value={summary?.totalRuns || 0}
          color="blue"
          icon={Activity}
        />
        <MetricCard
          label="Avg Verification Time"
          value={((summary?.avgVerificationTimeMs || 0) / 1000).toFixed(3)}
          unit="s"
          color="purple"
          icon={Clock}
        />
        <MetricCard
          label="Aggregation Latency (Last)"
          value={((latestRun?.fhe_sign_aggregation_ms || 0) / 1000).toFixed(2)}
          unit="s"
          color="green"
          icon={Zap}
        />
        <MetricCard
          label="Signature Size"
          value={latestRun?.aggregated_signature_size_bytes || 32}
          unit="Bytes"
          color="yellow"
          icon={Database}
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Charts Section - Now spanning 3 columns on large screens for side-by-side */}
        <div className="lg:col-span-3 grid grid-cols-1 md:grid-cols-2 gap-6">
          <ExecutionTimeChart data={data} />
          <StageDistributionChart data={data} />
          <TimelineChart data={data} />
          <GasUsageChart data={data} />
          <TransactionSizeChart data={data} />
          <ExecutionTimeDistributionChart data={data} />
        </div>

        {/* Bottom Section: Recent Runs & Blockchain Status */}
        <div className="lg:col-span-2">
          <RecentRunsTable data={data as ExperimentResult[]} />
        </div>

        <div className="lg:col-span-1">
          <BlockchainStatus
            recentTxHash={latestRun?.tx_hash}
            recentTxStatus={latestRun?.tx_status}
            recentValidity={latestRun?.validity}
          />
        </div>
      </div>
    </div>
  );
}

// Helper Components (Internal for now, can be extracted)

// Helper Components (Internal for now, can be extracted)

// Helper Components (Internal for now, can be extracted)

import { Activity, Clock, Zap, Database, CheckCircle2 } from 'lucide-react';

function MetricCard({ label, value, unit, color, icon: Icon }: { label: string, value: string | number, unit?: string, color: string, icon: any }) {
  // Map colors to gradients/text styles for glassmorphism
  const colorStyles: Record<string, string> = {
    blue: 'text-blue-400 from-blue-500/20 to-blue-600/5',
    purple: 'text-purple-400 from-purple-500/20 to-purple-600/5',
    green: 'text-emerald-400 from-emerald-500/20 to-emerald-600/5',
    yellow: 'text-yellow-400 from-yellow-500/20 to-yellow-600/5',
  };

  return (
    <div className={`glass-card p-6 bg-gradient-to-br ${colorStyles[color]} relative overflow-hidden group`}>
      <div className="relative z-10">
        <div className="flex justify-between items-start mb-2">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{label}</p>
          <Icon className={`w-5 h-5 opacity-50 group-hover:opacity-100 transition-opacity ${colorStyles[color].split(' ')[0]}`} />
        </div>
        <div className="flex items-baseline gap-1">
          <h2 className={`text-3xl font-bold ${colorStyles[color].split(' ')[0]} bg-clip-text text-transparent bg-gradient-to-r from-white to-white/70`}>
            {value}
          </h2>
          {unit && <span className="text-sm text-slate-500">{unit}</span>}
        </div>
      </div>

      {/* Decorative Glow */}
      <div className={`absolute -right-4 -bottom-4 w-24 h-24 rounded-full blur-2xl opacity-10 bg-current transition-opacity group-hover:opacity-20`} />
    </div>
  );
}

function RecentRunsTable({ data }: { data: ExperimentResult[] }) {
  return (
    <div className="glass-card h-full p-6">
      <div className="flex justify-between items-center mb-4">
        <h3 className="font-bold text-lg text-slate-200">Recent Simulations</h3>
        <span className="text-xs text-slate-400">Showing last 5 runs</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-700/50">
              <th className="py-3 px-2 font-medium text-slate-400">Total Ratings</th>
              <th className="py-3 px-2 font-medium text-slate-400">Total Time (s)</th>
              <th className="py-3 px-2 font-medium text-slate-400">Encryption (s)</th>
              <th className="py-3 px-2 font-medium text-slate-400">Aggregation (s)</th>
              <th className="py-3 px-2 font-medium text-slate-400">Sig Size</th>
              <th className="py-3 px-2 font-medium text-slate-400">Gas Used</th>
            </tr>
          </thead>
          <tbody>
            {data.slice(-5).reverse().map((run, i) => (
              <tr key={i} className="border-b border-slate-800/50 last:border-0 hover:bg-white/5 transition-colors">
                <td className="py-3 px-2 font-mono font-bold text-blue-400">{run.dataset_size}</td>
                <td className="py-3 px-2 flex items-center gap-1 text-slate-200">
                  {((run.total_execution_ms || 0) / 1000).toFixed(2)}
                  <span className="text-[10px] text-slate-500">s</span>
                </td>
                <td className="py-3 px-2 text-slate-400">{((run.encrypt_sign_ms || 0) / 1000).toFixed(2)}</td>
                <td className="py-3 px-2 text-slate-400">{((run.fhe_sign_aggregation_ms || 0) / 1000).toFixed(2)}</td>
                <td className="py-3 px-2 text-slate-400">{run.aggregated_signature_size_bytes} B</td>
                <td className="py-3 px-2 font-mono text-xs text-slate-300">{run.gas_used.toLocaleString()}</td>
              </tr>
            ))}
            {data.length === 0 && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500 italic">
                  No simulation data available yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
