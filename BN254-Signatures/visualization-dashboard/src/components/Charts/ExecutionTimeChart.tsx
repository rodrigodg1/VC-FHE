"use client";

import {
    LineChart,
    Line,
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

export function ExecutionTimeChart({ data }: Props) {
    // Transform data to seconds
    const chartData = data.map(item => ({
        ...item,
        total_execution_s: (item.total_execution_ms || 0) / 1000,
        encrypt_sign_s: item.encrypt_sign_ms / 1000,
        fhe_sign_aggregation_s: item.fhe_sign_aggregation_ms / 1000
    }));

    return (
        <div className="glass-card p-6 h-full flex flex-col">
            <h3 className="font-bold text-lg mb-4 text-slate-200">Execution Time vs Total Ratings</h3>
            <div className="chart-container flex-grow relative">
                {data.length === 0 ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 border border-dashed border-slate-700 rounded-lg bg-white/5">
                        <p className="mb-2">No data yet</p>
                        <p className="text-xs">Run simulation to see metrics</p>
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart
                            data={chartData}
                            margin={{
                                top: 5,
                                right: 30,
                                left: 20,
                                bottom: 5,
                            }}
                        >
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                            <XAxis
                                dataKey="dataset_size"
                                stroke="#94a3b8"
                                label={{ value: 'Total of individual ratings', position: 'insideBottomRight', offset: -10, fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                            />
                            <YAxis
                                stroke="#94a3b8"
                                label={{ value: 'Time (s)', angle: -90, position: 'insideLeft', fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                            />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                                itemStyle={{ color: '#e2e8f0' }}
                                formatter={(value: number) => [value.toFixed(2), 'Seconds']}
                            />
                            <Legend />
                            <Line type="monotone" dataKey="total_execution_s" name="Total Time" stroke="var(--primary)" strokeWidth={2} />
                            <Line type="monotone" dataKey="encrypt_sign_s" name="Encrypt & Sign" stroke="#8b5cf6" />
                            <Line type="monotone" dataKey="fhe_sign_aggregation_s" name="Aggregation" stroke="#10b981" />
                        </LineChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}
