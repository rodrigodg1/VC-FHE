"use client";

import {
    ComposedChart,
    Line,
    Scatter,
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

export function GasUsageChart({ data }: Props) {
    // Process data to calculate averages per dataset size
    const grouped = data.reduce((acc, curr) => {
        if (!acc[curr.dataset_size]) {
            acc[curr.dataset_size] = { totalGas: 0, count: 0 };
        }
        acc[curr.dataset_size].totalGas += curr.gas_used;
        acc[curr.dataset_size].count += 1;
        return acc;
    }, {} as Record<number, { totalGas: number, count: number }>);

    const averages = Object.entries(grouped).map(([size, stats]) => ({
        dataset_size: Number(size),
        avg_gas: stats.totalGas / stats.count
    })).sort((a, b) => a.dataset_size - b.dataset_size);

    return (
        <div className="glass-card p-6 h-full flex flex-col">
            <h3 className="font-bold text-lg mb-4 text-slate-200">Gas Usage by Ratings Count</h3>
            <div className="chart-container flex-grow relative">
                {data.length === 0 ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 border border-dashed border-slate-700 rounded-lg bg-white/5">
                        <p className="mb-2">No data yet</p>
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <ComposedChart
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
                                type="number"
                                domain={['dataMin', 'dataMax']}
                                stroke="#94a3b8"
                                label={{ value: 'Total of individual ratings', position: 'insideBottomRight', offset: -10, fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                                allowDuplicatedCategory={false}
                            />
                            <YAxis
                                dataKey="gas_used"
                                stroke="#94a3b8"
                                label={{ value: 'Gas Used', angle: -90, position: 'insideLeft', fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                            />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                                itemStyle={{ color: '#e2e8f0' }}
                                cursor={{ strokeDasharray: '3 3' }}
                                formatter={(value: number) => [value.toLocaleString(), 'Gas Units']}
                            />
                            <Legend />

                            <Scatter
                                name="Individual Run"
                                data={data}
                                fill="#8b5cf6"
                                fillOpacity={0.6}
                                dataKey="gas_used"
                            />

                            <Line
                                data={averages}
                                dataKey="avg_gas"
                                name="Average Gas"
                                stroke="#10b981"
                                strokeWidth={3}
                                dot={{ r: 4, fill: '#10b981' }}
                                activeDot={{ r: 6 }}
                            />
                        </ComposedChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}
