"use client";

import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ReferenceLine,
    ResponsiveContainer
} from 'recharts';
import { ExperimentResult } from '@/types';

interface Props {
    data: ExperimentResult[];
}

export function TransactionSizeChart({ data }: Props) {
    const dataWithIndex = data.map((item, index) => ({
        ...item,
        runIndex: index + 1
    }));

    const totalRuns = data.length;
    const avgSize = totalRuns > 0
        ? data.reduce((acc, curr) => acc + curr.tx_size_bytes, 0) / totalRuns
        : 0;

    return (
        <div className="glass-card p-6 h-full flex flex-col">
            <h3 className="font-bold text-lg mb-4 text-slate-200">Transaction Size Analysis</h3>
            <div className="chart-container flex-grow relative">
                {data.length === 0 ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 border border-dashed border-slate-700 rounded-lg bg-white/5">
                        <p className="mb-2">No data yet</p>
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart
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
                                label={{ value: 'Size (Bytes)', angle: -90, position: 'insideLeft', fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                                domain={['dataMin - 100', 'dataMax + 100']}
                            />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                                itemStyle={{ color: '#e2e8f0' }}
                                cursor={{ fill: '#334155', opacity: 0.1 }}
                            />
                            <Legend />
                            <Bar
                                dataKey="tx_size_bytes"
                                name="Tx Size (Bytes)"
                                fill="#3b82f6"
                                radius={[4, 4, 0, 0]}
                            />
                            <ReferenceLine
                                y={avgSize}
                                label={{
                                    value: `Avg: ${avgSize.toFixed(0)} B`,
                                    fill: '#f43f5e',
                                    position: 'right'
                                }}
                                stroke="#f43f5e"
                                strokeDasharray="3 3"
                            />
                        </BarChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}
