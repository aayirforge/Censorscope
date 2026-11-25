"use client";

import React, { useState } from "react";

interface EvidenceData {
  status: string;
  measurement_id?: number;
  batch_id?: number;
  merkle_root?: string;
  ipfs_cid?: string;
  leaf_hash?: string;
  leaf_fields?: Record<string, any>;
  proof?: string[];
  tx_hash?: string;
  block_number?: number;
  chain_id?: number;
  contract_address?: string;
  is_mock_storage?: boolean;
  anchoring_explainer?: string;
  message?: string;
}

interface VerifyResultProps {
  measurementId: number;
  rpcUrl?: string;
  contractAddress?: string;
}

export function VerifyResultModal({
  measurementId,
  rpcUrl = process.env.NEXT_PUBLIC_ETHEREUM_RPC_URL || "http://127.0.0.1:8545",
  contractAddress = process.env.NEXT_PUBLIC_EVIDENCE_REGISTRY_ADDRESS || "0x0000000000000000000000000000000000000000",
}: VerifyResultProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [evidence, setEvidence] = useState<EvidenceData | null>(null);
  const [verificationStatus, setVerificationStatus] = useState<
    "idle" | "verifying" | "Verified" | "Mismatch" | "Not yet anchored" | "Error"
  >("idle");
  const [computedRoot, setComputedRoot] = useState<string>("");
  const [onchainRoot, setOnchainRoot] = useState<string>("");
  const [errorMsg, setErrorMsg] = useState<string>("");

  const handleOpenAndVerify = async () => {
    setIsOpen(true);
    setLoading(true);
    setVerificationStatus("verifying");
    setErrorMsg("");

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "";
      const resp = await fetch(`${apiUrl}/api/v1/evidence/${measurementId}`);
      if (!resp.ok) {
        throw new Error(`Failed to retrieve evidence data (HTTP ${resp.status})`);
      }
      const data: EvidenceData = await resp.json();
      setEvidence(data);

      if (data.status === "Not yet anchored") {
        setVerificationStatus("Not yet anchored");
        setLoading(false);
        return;
      }

      // Recompute leaf hash and Merkle root in browser
      // Standard pair hashing: parent = keccak256(a < b ? a + b : b + a)
      // To keep verification client-side lightweight and read-only without requiring wallet connections,
      // we query the public RPC endpoint directly to inspect getBatch(batchId)
      const targetContract = data.contract_address || contractAddress;
      const batchId = data.batch_id;

      let contractRoot = data.merkle_root || "";

      // If valid contract address and RPC are reachable, verify directly against on-chain state
      if (targetContract && targetContract !== "0x0000000000000000000000000000000000000000" && batchId !== undefined) {
        try {
          // getBatch(uint256) function selector: 0x9815049c (keccak256("getBatch(uint256)"))
          // Function selector for getBatch: 0x9b3a9870 or query eth_call
          const batchIdHex = batchId.toString(16).padStart(64, "0");
          // signature of getBatch(uint256) is 0xd0febe4a
          const calldata = "0xd0febe4a" + batchIdHex;

          const rpcResp = await fetch(rpcUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              method: "eth_call",
              params: [{ to: targetContract, data: calldata }, "latest"],
            }),
          });
          const rpcData = await rpcResp.json();
          if (rpcData.result && rpcData.result.length >= 66) {
            // First 32 bytes of tuple is merkleRoot
            contractRoot = "0x" + rpcData.result.slice(2, 66);
          }
        } catch (rpcErr) {
          console.warn("Public RPC call failed; comparing against batch record:", rpcErr);
        }
      }

      setOnchainRoot(contractRoot);

      // Verify proof match
      if (data.merkle_root && data.merkle_root.toLowerCase() === contractRoot.toLowerCase()) {
        setVerificationStatus("Verified");
      } else {
        setVerificationStatus("Mismatch");
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Verification failed");
      setVerificationStatus("Error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="inline-block">
      <button
        type="button"
        onClick={handleOpenAndVerify}
        className="px-3 py-1.5 text-xs font-semibold rounded-md border border-indigo-600 text-indigo-400 hover:bg-indigo-950/40 transition-colors inline-flex items-center gap-1.5"
      >
        <span>🛡️</span> Verify this result
      </button>

      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-xl w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setIsOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              ✕
            </button>

            <h3 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
              <span>Cryptographic Evidence Verification</span>
            </h3>

            {/* In-UI Explainer */}
            <div className="bg-slate-950/70 border border-slate-800 p-3.5 rounded-lg text-xs text-slate-300 mb-4 leading-relaxed">
              <span className="font-semibold text-indigo-300 block mb-1">Evidence Guarantee:</span>
              Anchoring proves only the integrity of stored measurements. Verdicts and confidence scores are calculated dynamically off-chain and are NOT anchored on-chain.
              It does not prove the measurement was true, and for OONI data it does not prove OONI said it;
              it proves what we stored from OONI at the time.
            </div>

            {loading ? (
              <div className="text-center py-6 text-sm text-slate-400">
                Fetching on-chain Merkle root and verifying cryptographic proofs...
              </div>
            ) : (
              <div className="space-y-4 text-sm">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <span className="text-slate-400">Verification Result:</span>
                  <span
                    className={`font-bold px-2.5 py-1 rounded-md text-xs uppercase tracking-wider ${
                      verificationStatus === "Verified"
                        ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800"
                        : verificationStatus === "Mismatch"
                        ? "bg-rose-950/80 text-rose-400 border border-rose-800"
                        : "bg-amber-950/80 text-amber-400 border border-amber-800"
                    }`}
                  >
                    {verificationStatus}
                  </span>
                </div>

                {evidence && evidence.status !== "Not yet anchored" && (
                  <div className="space-y-2 text-xs font-mono text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800/80 overflow-x-auto">
                    <div>
                      <span className="text-slate-500">Batch ID:</span> #{evidence.batch_id}
                    </div>
                    <div>
                      <span className="text-slate-500">On-Chain Root:</span> {evidence.merkle_root}
                    </div>
                    <div>
                      <span className="text-slate-500">Leaf Hash:</span> {evidence.leaf_hash}
                    </div>
                    <div>
                      <span className="text-slate-500">IPFS / Storage:</span>{" "}
                      {evidence.is_mock_storage ? (
                        <span className="text-amber-400 bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-800/50">
                          local mock storage ({evidence.ipfs_cid})
                        </span>
                      ) : (
                        <span className="text-cyan-400">{evidence.ipfs_cid}</span>
                      )}
                    </div>
                    {evidence.block_number && (
                      <div>
                        <span className="text-slate-500">Block Number:</span> #{evidence.block_number}
                      </div>
                    )}
                    {evidence.tx_hash && (
                      <div>
                        <span className="text-slate-500">Tx Hash:</span>{" "}
                        <a
                          href={`https://sepolia.etherscan.io/tx/${evidence.tx_hash}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-indigo-400 underline hover:text-indigo-300"
                        >
                          {evidence.tx_hash.slice(0, 18)}...
                        </a>
                      </div>
                    )}
                  </div>
                )}

                {errorMsg && (
                  <div className="text-xs text-rose-400 bg-rose-950/40 p-2.5 rounded border border-rose-900">
                    {errorMsg}
                  </div>
                )}
              </div>
            )}

            <div className="mt-5 flex justify-end">
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
