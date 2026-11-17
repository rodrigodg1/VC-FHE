"use client";

import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer
} from 'recharts';
import { ExperimentResult } from '@/types';

interface Props {
    data: ExperimentResult[];
}

export function StageDistributionChart({ data }: Props) {
    // Show all runs to compare distribution across dataset sizes
    const chartData = data.map(item => ({
        ...item,
        setup_s: item.setup_ms / 1000,
        encrypt_sign_s: item.encrypt_sign_ms / 1000,
        fhe_sign_aggregation_s: item.fhe_sign_aggregation_ms / 1000,
        verification_s: item.verification_tx_s
    }));

    return (
        <div className="glass-card p-6 h-full flex flex-col">
            <h3 className="font-bold text-lg mb-4 text-slate-200">Stage Distribution (All Runs)</h3>
            <div className="chart-container flex-grow relative">
                {data.length === 0 ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 border border-dashed border-slate-700 rounded-lg bg-white/5">
                        <p className="mb-2">No data yet</p>
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                            data={chartData}
                            margin={{
                                top: 20,
                                right: 30,
                                left: 20,
                                bottom: 5,
                            }}
                        >
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                            <XAxis
                                dataKey="dataset_size"
                                stroke="#94a3b8"
                                label={{ value: 'Total Ratings', position: 'insideBottom', offset: -5, fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                            />
                            <YAxis
                                stroke="#94a3b8"
                                tick={{ fill: '#94a3b8' }}
                                label={{ value: 'Time (s)', angle: -90, position: 'insideLeft', fill: '#94a3b8' }}
                            />
                            <Tooltip
                                cursor={{ fill: '#334155', opacity: 0.1 }}
                                contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                                itemStyle={{ color: '#e2e8f0' }}
                                formatter={(value: number) => [value.toFixed(3), 'Seconds']}
                            />
                            <Legend />
                            <Bar dataKey="setup_s" name="Setup" stackId="a" fill="#64748b" />
                            <Bar dataKey="encrypt_sign_s" name="Encrypt" stackId="a" fill="#8b5cf6" />
                            <Bar dataKey="fhe_sign_aggregation_s" name="Aggregation" stackId="a" fill="#10b981" />
                            <Bar dataKey="verification_s" name="Verification" stackId="a" fill="#f59e0b" />
                        </BarChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}
