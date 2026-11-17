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

export function TimelineChart({ data }: Props) {
    // Add an index to each data point for the X-axis and convert to seconds
    const dataWithIndex = data.map((item, index) => ({
        ...item,
        runIndex: index + 1,
        total_execution_s: (item.total_execution_ms || 0) / 1000
    }));

    return (
        <div className="glass-card p-6 h-full flex flex-col">
            <h3 className="font-bold text-lg mb-4 text-slate-200">Execution Stability</h3>
            <div className="chart-container flex-grow relative">
                {data.length === 0 ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 border border-dashed border-slate-700 rounded-lg bg-white/5">
                        <p className="mb-2">No data yet</p>
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart
                            data={dataWithIndex}
                            margin={{
                                top: 5,
                                right: 30,
                                left: 20,
                                bottom: 5,
                            }}
                        >
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                            <XAxis
                                dataKey="runIndex"
                                stroke="#94a3b8"
                                label={{ value: 'Run Sequence #', position: 'insideBottomRight', offset: -10, fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                            />
                            <YAxis
                                stroke="#94a3b8"
                                label={{ value: 'Total Time (s)', angle: -90, position: 'insideLeft', fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                            />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                                itemStyle={{ color: '#e2e8f0' }}
                                labelFormatter={(label) => `Run #${label}`}
                                formatter={(value: number) => [value.toFixed(2), 'Seconds']}
                            />
                            <Legend />
                            <Line
                                type="monotone"
                                dataKey="total_execution_s"
                                name="Total Execution Time"
                                stroke="#f59e0b"
                                dot={false}
                                strokeWidth={2}
                            />
                        </LineChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}
