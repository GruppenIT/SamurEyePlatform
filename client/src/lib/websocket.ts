import { useEffect, useRef, useState, useCallback } from 'react';

export interface WebSocketMessage {
  type: string;
  data?: any;
  message?: string;
}

export function useWebSocket() {
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();
  const isMounted = useRef(true);

  const connect = useCallback(() => {
    // Don't reconnect if component is unmounted
    if (!isMounted.current) return;

    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws`;

      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        if (!isMounted.current) return;
        setConnected(true);
        if (reconnectTimer.current) {
          clearTimeout(reconnectTimer.current);
          reconnectTimer.current = undefined;
        }
      };

      ws.current.onmessage = (event) => {
        if (!isMounted.current) return;
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          setLastMessage(message);
        } catch (error) {
          console.error('Erro ao parsear mensagem WebSocket:', error);
        }
      };

      ws.current.onclose = () => {
        if (!isMounted.current) return;
        setConnected(false);

        // Attempt to reconnect after 5 seconds (only if still mounted)
        reconnectTimer.current = setTimeout(() => {
          if (isMounted.current) {
            connect();
          }
        }, 5000);
      };

      ws.current.onerror = () => {
        if (!isMounted.current) return;
        setConnected(false);
      };

    } catch (error) {
      console.error('Erro ao conectar WebSocket:', error);
      if (isMounted.current) {
        setConnected(false);
      }
    }
  }, []);

  useEffect(() => {
    isMounted.current = true;
    connect();

    return () => {
      isMounted.current = false;
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
        reconnectTimer.current = undefined;
      }
      if (ws.current) {
        // Remove onclose to prevent reconnection attempt after cleanup
        ws.current.onclose = null;
        ws.current.close();
        ws.current = null;
      }
    };
  }, [connect]);

  const sendMessage = useCallback((message: any) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(message));
    }
  }, []);

  return {
    connected,
    lastMessage,
    sendMessage,
  };
}
