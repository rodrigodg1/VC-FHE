export interface ExperimentResult {
    dataset_size: number;
    setup_ms: number;
    encrypt_sign_ms: number;
    fhe_sign_aggregation_ms: number;
    verification_tx_s: number;
    gas_used: number;
    tx_status: string;
    tx_hash: string;
    tx_size_bytes: number;
    aggregated_signature_size_bytes: number;
    validity?: string;
    // Computed fields
    total_execution_ms?: number;
}

export interface MetricsResponse {
    data: ExperimentResult[];
    lastUpdated: string;
    summary: {
        totalRuns: number;
        avgGasUsed: number;
        avgVerificationTimeMs: number;
    };
}
