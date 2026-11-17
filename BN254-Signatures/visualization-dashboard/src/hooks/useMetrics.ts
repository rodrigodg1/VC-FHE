"use client";

import { useEffect, useState } from 'react';
import { MetricsResponse, ExperimentResult } from '@/types';

export function useMetrics(refreshIntervalMs = 3000) {
    const [data, setData] = useState<ExperimentResult[]>([]);
    const [summary, setSummary] = useState<MetricsResponse['summary'] | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [lastUpdated, setLastUpdated] = useState<string | null>(null);

    useEffect(() => {
        const fetchMetrics = async () => {
            try {
                const response = await fetch('/api/metrics');
                if (!response.ok) {
                    throw new Error('Failed to fetch metrics');
                }
                const result: MetricsResponse = await response.json();

                // Add computed fields if needed
                const processedData = result.data.map(d => ({
                    ...d,
                    total_execution_ms: d.setup_ms + d.encrypt_sign_ms + d.fhe_sign_aggregation_ms + (d.verification_tx_s * 1000)
                }));

                setData(processedData);
                setSummary(result.summary);
                setLastUpdated(result.lastUpdated);
                setError(null);
            } catch (err) {
                console.error(err);
                setError('Error connecting to simulation backend');
            } finally {
                setLoading(false);
            }
        };

        fetchMetrics();
        const interval = setInterval(fetchMetrics, refreshIntervalMs);

        return () => clearInterval(interval);
    }, [refreshIntervalMs]);

    return { data, summary, loading, error, lastUpdated };
}
