package com.example.aura;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Hiểu request Salesforce Aura/Lightning và tách nó thành các "endpoint" theo từng action.
 *
 * <p>Mọi request Aura đều POST tới {@code /aura}, nên không thể định danh API theo URL path.
 * Đơn vị API thật sự nằm trong body: {@code message} là JSON chứa mảng {@code actions[]},
 * mỗi action có một {@code descriptor} (controller + action) và một object {@code params}.
 *
 * <p>Với mỗi action, lớp này sinh ra:
 * <ul>
 *   <li>{@code endpoint}: định danh ổn định từ descriptor (vd
 *       {@code ui.analytics...DashboardComponentController/getSitePathPrefix});
 *       riêng {@code ApexActionController/execute} còn gắn thêm {@code #namespace.class.method}
 *       để mỗi Apex method là một endpoint riêng.</li>
 *   <li>{@code params}: TẤT CẢ tên tham số, flatten đệ quy theo dotted-path để không bỏ sót
 *       (object -> {@code a.b.c}, mảng -> {@code a[]}, tới tận lá).</li>
 * </ul>
 */
final class AuraActionExtractor {

    private AuraActionExtractor() {}

    /** Một action Aura đã bóc tách: endpoint định danh + tập tên param. */
    static final class AuraAction {
        final String endpoint;
        final Set<String> params;

        AuraAction(String endpoint, Set<String> params) {
            this.endpoint = endpoint;
            this.params = params;
        }
    }

    /**
     * Trả về danh sách action nếu đây là request Aura, hoặc {@code null} nếu không phải
     * (để caller xử lý theo đường thông thường). Danh sách có thể rỗng nếu message không có action.
     */
    static List<AuraAction> extract(HttpRequest request) {
        if (request == null) return null;
        try {
            // POST: message nằm trong body (x-www-form-urlencoded).
            String body = request.bodyToString();
            if (body != null && body.indexOf("message=") >= 0) {
                return extractFromBody(body);
            }
            // GET: message nằm ở query string trên URL (?message=...&aura.context=...).
            return extractFromBody(request.query());
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Phần parse thuần theo body (tách riêng để test không cần HttpRequest). */
    static List<AuraAction> extractFromBody(String body) {
        if (body == null || body.isEmpty() || body.indexOf("message=") < 0) return null;

        String messageValue = formValue(body, "message");
        if (messageValue == null || !Json.looksLikeJson(messageValue)) return null;

        Object root;
        try {
            root = Json.parse(messageValue);
        } catch (RuntimeException e) {
            return null; // không parse được -> coi như không phải Aura hợp lệ
        }
        if (!(root instanceof Map)) return null;

        Object actionsObj = ((Map<?, ?>) root).get("actions");
        if (!(actionsObj instanceof List)) return null;

        List<AuraAction> result = new ArrayList<>();
        for (Object actObj : (List<?>) actionsObj) {
            if (!(actObj instanceof Map)) continue;
            Map<?, ?> action = (Map<?, ?>) actObj;

            Object descriptor = action.get("descriptor");
            if (!(descriptor instanceof String)) continue;

            Object paramsObj = action.get("params");
            String endpoint = normalizeDescriptor((String) descriptor, paramsObj);

            Set<String> params = new TreeSet<>();
            collectParamNames("", paramsObj, params);

            result.add(new AuraAction(endpoint, params));
        }
        return result;
    }

    /** Lấy value của một key trong body x-www-form-urlencoded (đã URL-decode). */
    private static String formValue(String body, String key) {
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            if (urlDecode(k).equals(key)) {
                return urlDecode(eq >= 0 ? pair.substring(eq + 1) : "");
            }
        }
        return null;
    }

    /**
     * Biến descriptor thành định danh endpoint gọn, ổn định.
     * {@code serviceComponent://pkg.FooController/ACTION$bar} -> {@code pkg.FooController/bar}.
     * Với {@code ApexActionController/execute} gắn thêm {@code #ns.Class.method}.
     */
    private static String normalizeDescriptor(String descriptor, Object paramsObj) {
        String d = descriptor;
        int scheme = d.indexOf("://");
        if (scheme >= 0) d = d.substring(scheme + 3);
        d = d.replace("/ACTION$", "/");

        if (d.equals("ApexActionController/execute") && paramsObj instanceof Map) {
            Map<?, ?> p = (Map<?, ?>) paramsObj;
            String cls = asString(p.get("classname"));
            String method = asString(p.get("method"));
            if (cls != null && method != null) {
                String ns = asString(p.get("namespace"));
                String prefix = (ns == null || ns.isEmpty()) ? "" : ns + ".";
                d = d + "#" + prefix + cls + "." + method;
            }
        }
        return d;
    }

    /**
     * Thu thập TẤT CẢ tên tham số theo dotted-path, đệ quy qua object và mảng.
     * Object: thêm đường dẫn mỗi key rồi đi tiếp. Mảng: dùng hậu tố {@code []}.
     * Mục tiêu: không bỏ sót bất kỳ tham số nào ở mọi độ sâu.
     */
    private static void collectParamNames(String prefix, Object node, Set<String> out) {
        if (node instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) node).entrySet()) {
                String path = prefix.isEmpty() ? String.valueOf(e.getKey()) : prefix + "." + e.getKey();
                out.add(path);
                collectParamNames(path, e.getValue(), out);
            }
        } else if (node instanceof List) {
            String path = prefix.isEmpty() ? "[]" : prefix + "[]";
            for (Object item : (List<?>) node) {
                collectParamNames(path, item, out);
            }
        } else {
            // Lá: đường dẫn đã được thêm ở nhánh Map; thêm lần nữa cho an toàn (TreeSet tự khử trùng).
            if (!prefix.isEmpty()) out.add(prefix);
        }
    }

    private static String asString(Object o) {
        return o instanceof String ? (String) o : null;
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }
}
