import React, { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import api from "../../api/scanApi";
import "./quanta_chatbot.css";
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

/**
 * QuantaChatbot — AI chatbot powered by Groq LLM.
 *
 * Quanta has full context of the scan report and can explain
 * quantum security concepts, scan results, and migration steps
 * in plain language to non-technical users.
 *
 * Props:
 *   cbom        – Cryptographic Bill of Materials (scan output)
 *   scanResults – Raw scan results array
 *   scanId      – Scan identifier
 */

const SUGGESTIONS = [
  "What does my scan report mean?",
  "Is my server safe from quantum attacks?",
  "What is HNDL / Harvest Now Decrypt Later?",
  "Explain PQC migration steps",
  "What is Mosca Inequality?",
  "What should I do first?",
];

export default function QuantaChatbot({ cbom, scanResults, scanId }) {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  // Auto-scroll to bottom
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 300);
    }
  }, [isOpen]);

  // ── Build scan context for the system prompt ──
  const buildScanContext = useCallback(() => {
    if (!cbom && !scanResults) return null;
    return {
      cbom: cbom || null,
      scan_results: scanResults || [],
    };
  }, [cbom, scanResults]);

  // ── Send message with streaming ──
  const sendMessage = useCallback(
    async (text) => {
      if (!text.trim() || isStreaming) return;

      const userMsg = { role: "user", content: text.trim() };
      const updatedMessages = [...messages, userMsg];
      setMessages(updatedMessages);
      setInput("");
      setIsStreaming(true);

      // Add placeholder assistant message
      const assistantMsg = { role: "assistant", content: "" };
      setMessages((prev) => [...prev, assistantMsg]);

      try {
        const response = await fetch(`${API_BASE_URL}/api/v1/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            messages: updatedMessages.map((m) => ({
              role: m.role,
              content: m.content,
            })),
            scan_context: buildScanContext(),
          }),
        });

        if (!response.ok) {
          const err = await response.json();
          throw new Error(err.detail || "Chat request failed");
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let fullContent = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value, { stream: true });
          const lines = chunk.split("\n");

          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const data = line.slice(6).trim();

            if (data === "[DONE]") break;

            try {
              const parsed = JSON.parse(data);
              if (parsed.content) {
                fullContent += parsed.content;
                setMessages((prev) => {
                  const updated = [...prev];
                  updated[updated.length - 1] = {
                    role: "assistant",
                    content: fullContent,
                  };
                  return updated;
                });
              }
              if (parsed.error) {
                fullContent += `\n\n⚠️ Error: ${parsed.error}`;
                setMessages((prev) => {
                  const updated = [...prev];
                  updated[updated.length - 1] = {
                    role: "assistant",
                    content: fullContent,
                  };
                  return updated;
                });
              }
            } catch {
              // Skip malformed JSON
            }
          }
        }
      } catch (err) {
        setMessages((prev) => {
          const updated = [...prev];
          updated[updated.length - 1] = {
            role: "assistant",
            content: `Sorry, I couldn't connect to the server. Please make sure the backend is running and GROQ_API_KEY is set.\n\n*Error: ${err.message}*`,
          };
          return updated;
        });
      } finally {
        setIsStreaming(false);
      }
    },
    [messages, isStreaming, buildScanContext]
  );

  // ── Handle key press ──
  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  // ── Simple markdown-ish rendering ──
  const renderContent = (text) => {
    if (!text) return null;

    return text.split("\n").map((line, i) => {
      // Bold
      let processed = line.replace(
        /\*\*(.*?)\*\*/g,
        "<strong>$1</strong>"
      );
      // Inline code
      processed = processed.replace(
        /`(.*?)`/g,
        "<code>$1</code>"
      );
      // Italic
      processed = processed.replace(
        /\*(.*?)\*/g,
        "<em>$1</em>"
      );
      // Bullet points
      if (processed.startsWith("- ") || processed.startsWith("• ")) {
        processed = "• " + processed.slice(2);
      }

      return (
        <p
          key={i}
          dangerouslySetInnerHTML={{ __html: processed || "&nbsp;" }}
        />
      );
    });
  };

  return (
    <>
      {/* ─── Floating avatar trigger ─── */}
      <AnimatePresence>
        {!isOpen && (
          <motion.div
            className="quanta-trigger"
            onClick={() => setIsOpen(true)}
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            transition={{ type: "spring", stiffness: 400, damping: 25 }}
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.95 }}
            title="Chat with Quanta AI"
          >
            <img src="/quanta_avatar.png" alt="Quanta AI" />
          </motion.div>
        )}
      </AnimatePresence>

      {/* ─── Backdrop ─── */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            className="quanta-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setIsOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* ─── Chat panel ─── */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            className="quanta-panel"
            initial={{ opacity: 0, y: 30, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 30, scale: 0.95 }}
            transition={{ type: "spring", stiffness: 350, damping: 28 }}
          >
            {/* Header */}
            <div className="quanta-header">
              <div className="quanta-header-avatar">
                <img src="/quanta_avatar.png" alt="Quanta" />
              </div>
              <div className="quanta-header-info">
                <div className="quanta-header-name">Quanta</div>
                <div className="quanta-header-status">
                  <span className="quanta-status-dot" />
                  QScan AI Assistant
                </div>
              </div>
              <button
                className="quanta-close"
                onClick={() => setIsOpen(false)}
              >
                ✕
              </button>
            </div>

            {/* Messages */}
            <div className="quanta-messages">
              {messages.length === 0 && (
                <motion.div
                  className="quanta-welcome"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                >
                  <div className="quanta-welcome-avatar">
                    <img src="/quanta_avatar.png" alt="Quanta" />
                  </div>
                  <div className="quanta-welcome-title">
                    Hi, I'm Quanta! 👋
                  </div>
                  <div className="quanta-welcome-text">
                    I've analyzed your scan report and I'm ready to help you
                    understand the results. Ask me anything about quantum
                    security, your risk scores, or what steps to take next.
                  </div>
                  <div className="quanta-suggestions">
                    {SUGGESTIONS.map((s, i) => (
                      <motion.button
                        key={i}
                        className="quanta-chip"
                        onClick={() => sendMessage(s)}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.3 + i * 0.08 }}
                      >
                        {s}
                      </motion.button>
                    ))}
                  </div>
                </motion.div>
              )}

              {messages.map((msg, idx) => (
                <motion.div
                  key={idx}
                  className={`quanta-msg quanta-msg-${msg.role}`}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  {msg.role === "assistant" ? (
                    <div className="quanta-msg-avatar">
                      <img src="/quanta_avatar.png" alt="Quanta" />
                    </div>
                  ) : (
                    <div className="quanta-msg-user-icon">U</div>
                  )}

                  <div
                    className={`quanta-bubble quanta-bubble-${msg.role}`}
                  >
                    {msg.role === "assistant" && !msg.content && isStreaming ? (
                      <div className="quanta-typing">
                        <span className="quanta-typing-dot" />
                        <span className="quanta-typing-dot" />
                        <span className="quanta-typing-dot" />
                      </div>
                    ) : (
                      renderContent(msg.content)
                    )}
                  </div>
                </motion.div>
              ))}

              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="quanta-input-area">
              <textarea
                ref={inputRef}
                className="quanta-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask Quanta about your scan..."
                rows={1}
                disabled={isStreaming}
              />
              <button
                className="quanta-send"
                onClick={() => sendMessage(input)}
                disabled={!input.trim() || isStreaming}
                title="Send message"
              >
                ➤
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
