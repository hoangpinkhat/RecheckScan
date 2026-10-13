package com.example.aura;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free JSON parser.
 * Parses into Map / List / String / Double / Boolean / null.
 * Used to read the Aura {@code message} payload so we can enumerate actions and params.
 */
final class Json {

    private Json() {}

    static Object parse(String text) {
        Parser p = new Parser(text);
        p.skipWs();
        Object v = p.readValue();
        p.skipWs();
        if (!p.end()) throw new JsonException("Trailing characters at " + p.pos);
        return v;
    }

    static boolean looksLikeJson(String s) {
        if (s == null) return false;
        String t = s.trim();
        if (t.isEmpty()) return false;
        char c = t.charAt(0);
        return c == '{' || c == '[';
    }

    static final class JsonException extends RuntimeException {
        JsonException(String msg) { super(msg); }
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) { this.s = s; }

        boolean end() { return pos >= s.length(); }

        void skipWs() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Object readValue() {
            skipWs();
            if (end()) throw new JsonException("Unexpected end of input");
            char c = s.charAt(pos);
            switch (c) {
                case '{': return readObject();
                case '[': return readArray();
                case '"': return readString();
                case 't': case 'f': return readBool();
                case 'n': return readNull();
                default: return readNumber();
            }
        }

        private Map<String, Object> readObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++; // {
            skipWs();
            if (!end() && s.charAt(pos) == '}') { pos++; return map; }
            while (true) {
                skipWs();
                if (end() || s.charAt(pos) != '"') throw new JsonException("Expected key at " + pos);
                String key = readString();
                skipWs();
                if (end() || s.charAt(pos) != ':') throw new JsonException("Expected ':' at " + pos);
                pos++;
                map.put(key, readValue());
                skipWs();
                if (end()) throw new JsonException("Unterminated object");
                char c = s.charAt(pos++);
                if (c == '}') break;
                if (c != ',') throw new JsonException("Expected ',' or '}' at " + (pos - 1));
            }
            return map;
        }

        private List<Object> readArray() {
            List<Object> list = new ArrayList<>();
            pos++; // [
            skipWs();
            if (!end() && s.charAt(pos) == ']') { pos++; return list; }
            while (true) {
                list.add(readValue());
                skipWs();
                if (end()) throw new JsonException("Unterminated array");
                char c = s.charAt(pos++);
                if (c == ']') break;
                if (c != ',') throw new JsonException("Expected ',' or ']' at " + (pos - 1));
            }
            return list;
        }

        private String readString() {
            StringBuilder sb = new StringBuilder();
            pos++; // opening quote
            while (true) {
                if (end()) throw new JsonException("Unterminated string");
                char c = s.charAt(pos++);
                if (c == '"') break;
                if (c == '\\') {
                    if (end()) throw new JsonException("Unterminated escape");
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"':  sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/':  sb.append('/'); break;
                        case 'n':  sb.append('\n'); break;
                        case 'r':  sb.append('\r'); break;
                        case 't':  sb.append('\t'); break;
                        case 'b':  sb.append('\b'); break;
                        case 'f':  sb.append('\f'); break;
                        case 'u':
                            if (pos + 4 > s.length()) throw new JsonException("Bad unicode escape");
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                            pos += 4;
                            break;
                        default: throw new JsonException("Bad escape");
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Object readBool() {
            if (s.startsWith("true", pos)) { pos += 4; return Boolean.TRUE; }
            if (s.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
            throw new JsonException("Invalid literal at " + pos);
        }

        private Object readNull() {
            if (s.startsWith("null", pos)) { pos += 4; return null; }
            throw new JsonException("Invalid literal at " + pos);
        }

        private Object readNumber() {
            int start = pos;
            while (!end()) {
                char c = s.charAt(pos);
                if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') pos++;
                else break;
            }
            String num = s.substring(start, pos);
            if (num.isEmpty()) throw new JsonException("Invalid value at " + start);
            try {
                return Double.parseDouble(num);
            } catch (NumberFormatException e) {
                throw new JsonException("Invalid number: " + num);
            }
        }
    }
}
