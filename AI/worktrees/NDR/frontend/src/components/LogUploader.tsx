import { useState, useRef } from "react";
import { Upload, FileText, CheckCircle, AlertCircle } from "lucide-react";
import { incidentsApi } from "@/api/incidents";
import { useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";

export default function LogUploader() {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<{ incidents_found: number; total_events: number } | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  const handleFile = async (file: File) => {
    setUploading(true);
    setProgress(0);
    setResult(null);
    try {
      const res = await incidentsApi.uploadLogs(file, setProgress);
      setResult(res.data);
      toast.success(`Processed ${res.data.total_events} events, found ${res.data.incidents_found} incidents`);
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["analytics"] });
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? "Upload failed";
      toast.error(msg);
    } finally {
      setUploading(false);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      onClick={() => !uploading && inputRef.current?.click()}
      className={`
        card cursor-pointer transition-all duration-200 text-center
        ${dragging ? "border-blue-500 bg-blue-500/5" : "hover:border-slate-700"}
        ${uploading ? "cursor-not-allowed opacity-70" : ""}
      `}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".txt,.log,.json,.csv"
        className="hidden"
        onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
      />

      {uploading ? (
        <div className="space-y-3">
          <div className="w-10 h-10 mx-auto border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm text-slate-300">Analyzing logs... {progress}%</p>
          <div className="w-full bg-slate-800 rounded-full h-1.5">
            <div
              className="bg-blue-500 h-1.5 rounded-full transition-all"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      ) : result ? (
        <div className="space-y-2">
          <CheckCircle className="w-10 h-10 mx-auto text-green-400" />
          <p className="font-semibold text-white">Analysis Complete</p>
          <p className="text-sm text-slate-400">
            {result.total_events} events scanned · {result.incidents_found} incidents detected
          </p>
          <p className="text-xs text-slate-500 mt-2">Click or drop another file to upload again</p>
        </div>
      ) : (
        <div className="space-y-3">
          <Upload className="w-10 h-10 mx-auto text-slate-500" />
          <div>
            <p className="font-medium text-slate-300">Drop log file here or click to browse</p>
            <p className="text-sm text-slate-500 mt-1">Supports .txt, .log, .json, .csv · Max 50MB</p>
          </div>
          <div className="flex items-center justify-center gap-4 text-xs text-slate-600">
            <span className="flex items-center gap-1"><FileText size={12} /> JSON Lines</span>
            <span className="flex items-center gap-1"><FileText size={12} /> CSV</span>
            <span className="flex items-center gap-1"><FileText size={12} /> Plain Text</span>
          </div>
        </div>
      )}
    </div>
  );
}
