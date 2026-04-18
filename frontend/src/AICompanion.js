// AI Companion — Trend Micro Vision One Companion-style floating chat widget
import React, { useState, useRef, useEffect } from "react";
import axios from "axios";

const API_BASE = process.env.NODE_ENV === "development" ? "http://localhost:8000" : "";

function makeClient() {
  const token = localStorage.getItem("access_token");
  return axios.create({
    baseURL: API_BASE,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

const QUICK_PROMPTS = [
  "Summarize my posture",
  "Top 3 threats",
  "MITRE coverage",
  "How do I respond?",
];

export default function AICompanion({ focusedIncidentId = null }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content:
        "Hi — I'm your AI Security Companion. Ask me about your incidents, threats, or recommended actions. Try a quick prompt below or type a question.",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [meta, setMeta] = useState({ model: null, contextCount: 0 });
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, loading]);

  const send = async (text) => {
    const q = (text ?? input).trim();
    if (!q || loading) return;

    const newMessages = [...messages, { role: "user", content: q }];
    setMessages(newMessages);
    setInput("");
    setLoading(true);

    try {
      const history = newMessages
        .slice(0, -1)
        .filter((m) => m.role === "user" || m.role === "assistant")
        .map((m) => ({ role: m.role, content: m.content }));

      const res = await makeClient().post("/api/v1/ai/chat", {
        message: q,
        history,
        incident_id: focusedIncidentId,
      });

      setMessages((prev) => [...prev, { role: "assistant", content: res.data.reply }]);
      setMeta({ model: res.data.model, contextCount: res.data.incident_context_used });
    } catch (err) {
      const msg =
        err.response?.status === 401
          ? "Session expired. Please sign in again."
          : err.response?.data?.detail || "Failed to reach AI Companion.";
      setMessages((prev) => [...prev, { role: "assistant", content: `⚠ ${msg}` }]);
    } finally {
      setLoading(false);
    }
  };

  const onKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  // Floating launcher button
  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        title="AI Security Companion"
        style={{
          position: "fixed",
          bottom: 24,
          right: 24,
          zIndex: 9998,
          width: 58,
          height: 58,
          borderRadius: "50%",
          border: "1px solid rgba(100,180,255,0.4)",
          background:
            "linear-gradient(135deg, rgba(100,180,255,0.25), rgba(170,120,255,0.25))",
          color: "white",
          cursor: "pointer",
          fontSize: 24,
          fontWeight: 700,
          boxShadow: "0 8px 24px rgba(100,180,255,0.3)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          backdropFilter: "blur(8px)",
          transition: "transform 0.2s",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.transform = "scale(1.08)")}
        onMouseLeave={(e) => (e.currentTarget.style.transform = "scale(1)")}
      >
        ✦
      </button>
    );
  }

  return (
    <div
      style={{
        position: "fixed",
        bottom: 24,
        right: 24,
        zIndex: 9998,
        width: 420,
        maxWidth: "calc(100vw - 48px)",
        height: 620,
        maxHeight: "calc(100vh - 48px)",
        background: "rgba(20, 26, 40, 0.98)",
        border: "1px solid rgba(100,180,255,0.25)",
        borderRadius: 14,
        boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        backdropFilter: "blur(12px)",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "14px 18px",
          borderBottom: "1px solid rgba(255,255,255,0.08)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background:
            "linear-gradient(135deg, rgba(100,180,255,0.08), rgba(170,120,255,0.08))",
        }}
      >
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: "white" }}>
            ✦ AI Security Companion
          </div>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.45)", marginTop: 2 }}>
            {meta.model
              ? `${meta.model} · ${meta.contextCount} incidents in context`
              : "Ready"}
            {focusedIncidentId ? ` · focus: #${focusedIncidentId}` : ""}
          </div>
        </div>
        <button
          onClick={() => setOpen(false)}
          style={{
            background: "none",
            border: "none",
            color: "rgba(255,255,255,0.5)",
            fontSize: 22,
            cursor: "pointer",
            padding: "0 4px",
          }}
        >
          ×
        </button>
      </div>

      {/* Messages */}
      <div
        ref={scrollRef}
        style={{
          flex: 1,
          overflowY: "auto",
          padding: 16,
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        {messages.map((m, idx) => (
          <div
            key={idx}
            style={{
              alignSelf: m.role === "user" ? "flex-end" : "flex-start",
              maxWidth: "85%",
              background:
                m.role === "user"
                  ? "rgba(100,180,255,0.18)"
                  : "rgba(255,255,255,0.05)",
              border: `1px solid ${
                m.role === "user"
                  ? "rgba(100,180,255,0.3)"
                  : "rgba(255,255,255,0.08)"
              }`,
              padding: "10px 14px",
              borderRadius: 10,
              fontSize: 13.5,
              lineHeight: 1.55,
              color: "rgba(255,255,255,0.9)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {formatMarkdown(m.content)}
          </div>
        ))}
        {loading && (
          <div
            style={{
              alignSelf: "flex-start",
              background: "rgba(255,255,255,0.04)",
              padding: "10px 14px",
              borderRadius: 10,
              fontSize: 13,
              color: "rgba(255,255,255,0.5)",
            }}
          >
            <span className="ai-dots">Thinking</span>
          </div>
        )}
      </div>

      {/* Quick prompts */}
      {messages.length <= 1 && !loading && (
        <div
          style={{
            padding: "8px 12px",
            borderTop: "1px solid rgba(255,255,255,0.05)",
            display: "flex",
            gap: 6,
            flexWrap: "wrap",
          }}
        >
          {QUICK_PROMPTS.map((p) => (
            <button
              key={p}
              onClick={() => send(p)}
              style={{
                padding: "5px 12px",
                borderRadius: 14,
                border: "1px solid rgba(100,180,255,0.25)",
                background: "rgba(100,180,255,0.05)",
                color: "rgba(180,210,255,0.9)",
                fontSize: 12,
                cursor: "pointer",
              }}
            >
              {p}
            </button>
          ))}
        </div>
      )}

      {/* Input */}
      <div
        style={{
          padding: 12,
          borderTop: "1px solid rgba(255,255,255,0.08)",
          display: "flex",
          gap: 8,
        }}
      >
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKey}
          disabled={loading}
          placeholder="Ask about your incidents..."
          rows={1}
          style={{
            flex: 1,
            resize: "none",
            background: "rgba(255,255,255,0.05)",
            border: "1px solid rgba(255,255,255,0.12)",
            borderRadius: 8,
            padding: "10px 12px",
            color: "white",
            fontSize: 13.5,
            outline: "none",
            fontFamily: "inherit",
            maxHeight: 100,
          }}
        />
        <button
          onClick={() => send()}
          disabled={loading || !input.trim()}
          style={{
            padding: "0 18px",
            borderRadius: 8,
            border: "1px solid rgba(100,180,255,0.4)",
            background:
              loading || !input.trim()
                ? "rgba(100,180,255,0.1)"
                : "rgba(100,180,255,0.25)",
            color: "white",
            fontSize: 13,
            fontWeight: 600,
            cursor: loading || !input.trim() ? "default" : "pointer",
          }}
        >
          Send
        </button>
      </div>
    </div>
  );
}

// Tiny markdown renderer — bold + line breaks only (no external deps)
function formatMarkdown(text) {
  const parts = String(text).split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={i} style={{ color: "rgba(180,210,255,1)" }}>
          {part.slice(2, -2)}
        </strong>
      );
    }
    // Italic *text*
    const italicParts = part.split(/(\*[^*]+\*)/g);
    return italicParts.map((p, j) => {
      if (p.startsWith("*") && p.endsWith("*") && p.length > 2) {
        return (
          <em key={`${i}-${j}`} style={{ color: "rgba(255,255,255,0.65)" }}>
            {p.slice(1, -1)}
          </em>
        );
      }
      return <span key={`${i}-${j}`}>{p}</span>;
    });
  });
}
