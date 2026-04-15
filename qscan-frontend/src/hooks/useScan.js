
import { useState, useEffect, useCallback } from "react";
import { scanApi } from "../api/scanApi";
import { formatCBOMData } from "../utils/pqcClassifier";

export const useScan = (scanId) => {
  const [scan, setScan] = useState(null);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);

  const fetchStatus = useCallback(async () => {
    if (!scanId) return;

    try {
      const response = await scanApi.getScanStatus(scanId);
      const data = response.data;

      setScan(data);
      setProgress(data.progress || 0);

      if (data.logs) {
        setLogs(data.logs.slice(-30));
      }

      if (data.error) {
        setError(data.error);
      }

    } catch (err) {
      setError(err.message);
      console.error("Status fetch error:", err);
    }

  }, [scanId]);

  useEffect(() => {
    if (!scanId) return;

    fetchStatus();

    const interval = setInterval(fetchStatus, 1500);

    return () => clearInterval(interval);

  }, [scanId, fetchStatus]);

  return {
    scan,
    progress,
    logs,
    error,
    refetch: fetchStatus,
  };
};


export const useScanResults = (scanId) => {

  const [results, setResults] = useState(null);
  const [cbom, setCBOM] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchResults = useCallback(async () => {

    if (!scanId) return;

    setLoading(true);

    try {

      const [resultsRes, cbomRes] = await Promise.all([
        scanApi.getScanResults(scanId),
        scanApi.getCBOM(scanId),
      ]);

      setResults(resultsRes.data);

      const formatted = formatCBOMData(cbomRes.data);

      setCBOM(formatted);

    } catch (err) {

      setError(err.message);
      console.error("Results fetch error:", err);

    } finally {

      setLoading(false);

    }

  }, [scanId]);

  useEffect(() => {
    fetchResults();
  }, [fetchResults]);

  return {
  results,
  cbom,
  scanResults: results?.scan_results || [],
  loading,
  error,
  refetch: fetchResults,
};
};


export const useStartScan = () => {

  const [scanId, setScanId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const startScan = useCallback(async (target, scanTypes = [], discover = false) => {

    setLoading(true);
    setError(null);

    try {

      const response = await scanApi.startScan(target, scanTypes, discover);

      setScanId(response.data.scan_id);

      return response.data.scan_id;

    } catch (err) {

      const message = err.response?.data?.detail || err.message;

      setError(message);
      console.error("Start scan error:", err);

      throw err;

    } finally {

      setLoading(false);

    }

  }, []);

  return {
    scanId,
    loading,
    error,
    startScan,
  };
};

export function useScanHistory() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchHistory = useCallback(async () => {
    setLoading(true);

    try {
      const res = await scanApi.getHistory();
      setHistory(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.error(err);
      setError(err.message);
    }

    setLoading(false);
  }, []);

  useEffect(() => {
    fetchHistory();

    const interval = setInterval(fetchHistory, 30000); // Poll every 30 seconds

    return () => clearInterval(interval);
  }, []); // ✓ FIXED: Empty dependency array prevents infinite loop

  const deleteScan = async (scanId) => {
    try {
      await scanApi.deleteScan(scanId);
      setHistory((prev) => prev.filter((h) => h.scan_id !== scanId));
    } catch (err) {
      console.error(err);
    }
  };

  return {
    history,
    loading,
    error,
    refetch: fetchHistory,
    deleteScan,
  };
}
