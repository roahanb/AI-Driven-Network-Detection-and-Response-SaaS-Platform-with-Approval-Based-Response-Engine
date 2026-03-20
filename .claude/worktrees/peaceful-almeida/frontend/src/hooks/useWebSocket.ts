import { useEffect, useRef, useCallback } from "react";
import { useAuthStore } from "@/store/authStore";
import type { WsMessage, WsEventType } from "@/types";

type EventHandlers = Partial<Record<WsEventType, (data: Record<string, unknown>) => void>>;

const WS_URL = import.meta.env.VITE_WS_URL || `ws://${window.location.host}/ws`;

export function useWebSocket(handlers: EventHandlers) {
  const wsRef = useRef<WebSocket | null>(null);
  const pingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  const connect = useCallback(() => {
    const token = useAuthStore.getState().accessToken;
    if (!token) return;

    const ws = new WebSocket(`${WS_URL}?token=${token}`);
    wsRef.current = ws;

    ws.onopen = () => {
      console.debug("[WS] Connected");
      // Keep-alive ping every 25s
      pingRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send("ping");
      }, 25_000);
    };

    ws.onmessage = (evt) => {
      try {
        const msg: WsMessage = JSON.parse(evt.data);
        const handler = handlersRef.current[msg.event];
        if (handler) handler(msg.data);
      } catch {
        // ignore malformed messages
      }
    };

    ws.onclose = (e) => {
      console.debug("[WS] Closed:", e.code);
      if (pingRef.current) clearInterval(pingRef.current);
      // Reconnect unless intentional close
      if (e.code !== 1000 && e.code !== 4001) {
        reconnectRef.current = setTimeout(connect, 3_000);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (pingRef.current) clearInterval(pingRef.current);
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      wsRef.current?.close(1000, "Component unmounted");
    };
  }, [connect]);
}
