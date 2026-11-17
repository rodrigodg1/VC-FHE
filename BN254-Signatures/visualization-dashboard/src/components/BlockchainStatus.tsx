"use client";

import { useEffect, useState } from 'react';
import { ethers } from 'ethers';

export function BlockchainStatus({
    recentTxHash,
    recentTxStatus,
    recentValidity,
}: {
    recentTxHash?: string;
    recentTxStatus?: string;
    recentValidity?: string;
}) {
    const [blockNumber, setBlockNumber] = useState<number>(0);
    const [status, setStatus] = useState<'Connected' | 'Disconnected' | 'Connecting'>('Connecting');
    const [verifiedTx, setVerifiedTx] = useState<any>(null);

    useEffect(() => {
        let interval: NodeJS.Timeout;

        const connect = async () => {
            try {
                // Connect to hardhat default
                const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");
                await provider._detectNetwork(); // Ensure network is ready
                const block = await provider.getBlockNumber();
                setBlockNumber(block);
                setStatus('Connected');
            } catch (e) {
                setStatus('Disconnected');
            }
        };

        connect();
        interval = setInterval(connect, 3000); // Check faster

        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        if (recentTxHash && status === 'Connected') {
            // ... (Tx checking logic same as before, simplified for brevity in this thought trace)
            const checkTx = async () => {
                try {
                    const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");
                    const receipt = await provider.getTransactionReceipt(recentTxHash);
                    if (receipt) {
                        const verdict = receipt.status === 1 ? 'ACCEPT' : 'REJECT';
                        setVerifiedTx({
                            hash: receipt.hash,
                            blockNumber: receipt.blockNumber,
                            gasUsed: receipt.gasUsed.toString(),
                            status: receipt.status,
                            verdict
                        });
                    }
                } catch (e) {
                    console.error("Error fetching tx", e);
                }
            };
            checkTx();
        }
    }, [recentTxHash, status]);

    return (
        <div className="glass-card text-white h-full p-6">
            <div className="flex justify-between items-center mb-6">
                <h3 className="font-bold text-lg text-white">Blockchain Node</h3>
                <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold ${status === 'Connected' ? 'bg-emerald-900/50 text-emerald-400 border border-emerald-800' : 'bg-red-900/50 text-red-400 border border-red-800'}`}>
                    <div className={`w-2 h-2 rounded-full ${status === 'Connected' ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`}></div>
                    {status}
                </div>
            </div>

            <div className="space-y-6">
                <div className="p-4 rounded-lg bg-black/40 border border-white/5">
                    <p className="text-zinc-400 text-xs uppercase tracking-wider mb-1">Current Block Height</p>
                    <p className="text-3xl font-mono text-white">#{blockNumber.toLocaleString()}</p>
                </div>

                {recentTxHash ? (
                    <div className="border-t border-white/10 pt-4">
                        <div className="flex items-center justify-between mb-2">
                            <p className="text-zinc-400 text-sm font-medium">Latest Verification</p>
                            {verifiedTx?.status === 1 && <span className="text-xs text-emerald-400">Accept</span>}
                            {verifiedTx?.status === 0 && <span className="text-xs text-red-400">Reject</span>}
                        </div>

                        <div className="bg-black/40 p-3 rounded border border-white/5 font-mono text-xs break-all text-blue-300">
                            {recentTxHash}
                        </div>

                        {verifiedTx ? (
                            <div className="mt-3 grid grid-cols-2 gap-3">
                                <div className="bg-zinc-800/50 p-2 rounded">
                                    <span className="text-zinc-500 text-[10px] block">BLOCK</span>
                                    <span className="text-zinc-300">{verifiedTx.blockNumber}</span>
                                </div>
                                <div className="bg-zinc-800/50 p-2 rounded">
                                    <span className="text-zinc-500 text-[10px] block">GAS USED</span>
                                    <span className="text-zinc-300">{parseInt(verifiedTx.gasUsed).toLocaleString()}</span>
                                </div>
                                <div className="bg-zinc-800/50 p-2 rounded">
                                    <span className="text-zinc-500 text-[10px] block">COMPUTATION</span>
                                    <span className={verifiedTx.status === 1 ? "text-emerald-400" : "text-red-400"}>
                                        {verifiedTx.status === 1 ? "ACCEPT (verifiable computation)" : "REJECT (malicious node)"}
                                    </span>
                                </div>
                                <div className="bg-zinc-800/50 p-2 rounded">
                                    <span className="text-zinc-500 text-[10px] block">REPORTED VALIDITY</span>
                                    <span className="text-zinc-300">{recentValidity || recentTxStatus || "Unknown"}</span>
                                </div>
                            </div>
                        ) : (
                            <div className="mt-2 text-xs text-yellow-500 flex items-center gap-1">
                                <span className="animate-spin">⟳</span> Pending verification...
                            </div>
                        )}
                    </div>
                ) : (
                    <div className="text-center py-8 text-zinc-600 italic text-sm">
                        No transactions to verify
                    </div>
                )}
            </div>
        </div>
    );
}
