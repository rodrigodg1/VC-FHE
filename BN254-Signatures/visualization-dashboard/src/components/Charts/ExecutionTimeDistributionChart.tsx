"use client";

import {
    Bar,
    ComposedChart,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Customized,
    ResponsiveContainer
} from 'recharts';
import { ExperimentResult } from '@/types';

interface Props {
    data: ExperimentResult[];
}

interface Quartiles {
    min: number;
    q1: number;
    median: number;
    q3: number;
    max: number;
    dataset_size: number;
}

const BoxPlotOverlay = (props: any) => {
    const { xAxisMap, yAxisMap, data } = props;

    if (!xAxisMap || !yAxisMap || !data) return null;

    const xAxis = Object.values(xAxisMap)[0] as any;
    const yAxis = Object.values(yAxisMap)[0] as any;

    if (!xAxis || !yAxis || !xAxis.scale || !yAxis.scale) return null;

    const xScale = xAxis.scale;
    const yScale = yAxis.scale;
    const boxWidth = 20;

    return (
        <g>
            {data.map((item: Quartiles, index: number) => {
                const x = xScale(item.dataset_size);

                // Ensure x is a valid number
                if (typeof x !== 'number' || isNaN(x)) return null;

                const yMin = yScale(item.min);
                const yQ1 = yScale(item.q1);
                const yMedian = yScale(item.median);
                const yQ3 = yScale(item.q3);
                const yMax = yScale(item.max);

                return (
                    <g key={index}>
                        {/* Vertical Range Line (Min to Max) */}
                        <line x1={x} y1={yMin} x2={x} y2={yMax} stroke="#94a3b8" strokeWidth={1} />

                        {/* Whiskers */}
                        <line x1={x - boxWidth / 2} y1={yMax} x2={x + boxWidth / 2} y2={yMax} stroke="#94a3b8" strokeWidth={1} />
                        <line x1={x - boxWidth / 2} y1={yMin} x2={x + boxWidth / 2} y2={yMin} stroke="#94a3b8" strokeWidth={1} />

                        {/* Box (Q1 to Q3) */}
                        <rect
                            x={x - boxWidth / 2}
                            y={Math.min(yQ1, yQ3)} // y coordinates in SVG are top-down, but yScale handles mapping. 
                            // Recharts yScale: smaller value -> higher pixel y (usually).
                            // We should maintain valid rect dimensions.
                            width={boxWidth}
                            height={Math.abs(yQ1 - yQ3)}
                            fill="#8b5cf6"
                            fillOpacity={0.6}
                            stroke="#8b5cf6"
                        />

                        {/* Median Line */}
                        <line
                            x1={x - boxWidth / 2}
                            y1={yMedian}
                            x2={x + boxWidth / 2}
                            y2={yMedian}
                            stroke="#ffffff"
                            strokeWidth={2}
                        />
                    </g>
                );
            })}
        </g>
    );
};

export function ExecutionTimeDistributionChart({ data }: Props) {
    // 1. Group data by dataset_size
    const groups: Record<number, number[]> = {};
    data.forEach(item => {
        const val = (item.total_execution_ms || 0) / 1000;
        if (!groups[item.dataset_size]) groups[item.dataset_size] = [];
        groups[item.dataset_size].push(val);
    });

    // 2. Calculate Quartiles
    const quartilesData: Quartiles[] = Object.entries(groups).map(([size, values]) => {
        values.sort((a, b) => a - b);

        const min = values[0];
        const max = values[values.length - 1];

        // Simple quartile calculation
        const q1Index = Math.floor(values.length * 0.25);
        const medianIndex = Math.floor(values.length * 0.5);
        const q3Index = Math.floor(values.length * 0.75);

        return {
            dataset_size: Number(size),
            min,
            q1: values[q1Index],
            median: values[medianIndex],
            q3: values[q3Index],
            max
        };
    }).sort((a, b) => a.dataset_size - b.dataset_size);

    return (
        <div className="glass-card p-6 h-full flex flex-col">
            <h3 className="font-bold text-lg mb-4 text-slate-200">Execution Time Distribution (Box Plot)</h3>
            <div className="chart-container flex-grow relative">
                {data.length === 0 ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 border border-dashed border-slate-700 rounded-lg bg-white/5">
                        <p className="mb-2">No data yet</p>
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <ComposedChart
                            data={quartilesData}
                            margin={{
                                top: 20,
                                right: 30,
                                left: 20,
                                bottom: 20, // Increased bottom margin for labels
                            }}
                        >
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />

                            <XAxis
                                dataKey="dataset_size"
                                type="number"
                                domain={['dataMin', 'dataMax']}
                                stroke="#94a3b8"
                                label={{ value: 'Total of individual ratings', position: 'insideBottom', offset: -10, fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                                tickCount={quartilesData.length}
                                padding={{ left: 30, right: 30 }} // Ensure padding for the boxes
                            />

                            <YAxis
                                stroke="#94a3b8"
                                label={{ value: 'Time (s)', angle: -90, position: 'insideLeft', fill: '#94a3b8' }}
                                tick={{ fill: '#94a3b8' }}
                            />

                            <Tooltip
                                content={({ active, payload }) => {
                                    if (active && payload && payload.length) {
                                        // Payload comes from the Scatter primarily
                                        const d = payload[0].payload as Quartiles;
                                        return (
                                            <div className="bg-slate-800 border border-slate-700 p-2 rounded text-xs text-white">
                                                <p className="font-bold mb-1">Total Ratings: {d.dataset_size}</p>
                                                <div className="grid grid-cols-2 gap-x-2">
                                                    <span>Max:</span> <span className="text-right">{d.max.toFixed(3)}s</span>
                                                    <span>Q3:</span> <span className="text-right">{d.q3.toFixed(3)}s</span>
                                                    <span className="text-yellow-400">Median:</span> <span className="text-right text-yellow-400">{d.median.toFixed(3)}s</span>
                                                    <span>Q1:</span> <span className="text-right">{d.q1.toFixed(3)}s</span>
                                                    <span>Min:</span> <span className="text-right">{d.min.toFixed(3)}s</span>
                                                </div>
                                            </div>
                                        );
                                    }
                                    return null;
                                }}
                            />

                            {/* Invisible Bar to establish the domain and trigger tooltips on the columns */}
                            <Bar
                                dataKey="max"
                                fill="transparent"
                                legendType="none"
                            />

                            <Customized component={<BoxPlotOverlay data={quartilesData} />} />

                        </ComposedChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}
