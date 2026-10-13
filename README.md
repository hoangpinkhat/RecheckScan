# Recheck Scan — REST · GraphQL · Aura

[![Java](https://img.shields.io/badge/Java-17+-orange.svg)]()
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Montoya%20API-ff6633.svg)]()
[![SQLite](https://img.shields.io/badge/SQLite-bundled-green.svg)]()

Bộ extension Burp giúp **theo dõi trạng thái quét** của các endpoint/tham số: tự phát hiện từ
HTTP traffic, lưu SQLite, và cho biết cái nào **đã scan / chưa scan / rejected / bypassed**.

Repo có **3 bản** dùng chung kiến trúc (SQLite · tab Unscanned/Logs/Settings · trạng thái ·
highlight/note · auto-bypass), khác nhau ở **cách định danh "API" và cách trích tham số**:

| Bản | Định danh API | Tham số | Main class | JAR |
|-----|---------------|---------|-----------|-----|
| **REST** | `host + path + method` | param URL/body (JSON/XML/form/multipart) | `com.example.RecheckScanApiExtension` | `burp-recheck-scan-<ver>.jar` |
| **GraphQL** | `host + ` operation (query/mutation + tên) | field/argument trong query | `com.example.graphql.GraphQLRecheckScanExtension` | `burp-recheck-scan-graphql-<ver>.jar` |
| **Aura** | `host + ` action descriptor (Salesforce Lightning) | flatten đệ quy mọi key trong `action.params` | `com.example.aura.RecheckScanAuraExtension` | `burp-recheck-scan-aura-<ver>.jar` |

Mỗi bản là một BurpExtension độc lập; mỗi JAR chỉ chứa đúng một extension.

## Vì sao cần bản riêng

- **REST**: `(host, path, method)` là đủ để phân biệt endpoint.
- **GraphQL**: mọi request thường POST về **một** `/graphql` → phải định danh theo **operation**,
  và trích field/argument bên trong query.
- **Aura/Lightning**: mọi request POST/GET về **`/aura`**, action thật nằm trong `message` (JSON,
  có khi lồng/escaped). Định danh theo **descriptor** của từng action; **flatten đệ quy** params
  để không bỏ sót (object → `a.b.c`, mảng → `a[]`). Hỗ trợ cả request **POST (body)** lẫn
  **GET (query string)**.

## Điểm nổi bật bản Aura

- Mỗi action trong một request (kể cả batch) = **một endpoint riêng**; `ApexActionController/execute`
  gắn thêm `#namespace.Class.method`.
- Chuột phải trong bảng: **Send to Repeater**, **Send to Active Scan** (dồn vào một audit dùng chung),
  **Copy request**, **Copy API List**. `Ctrl+C` = copy cả request thô.
- Bộ đếm trên mỗi bảng: *đang hiện / tổng · Scanned · Unscanned · Bypass · Rejected*.

## Build

Yêu cầu **JDK 17+** và **Maven**.

```bash
mvn clean package
```

Tạo ra 3 JAR trong `target/`:
- `burp-recheck-scan-<ver>.jar` — bản REST
- `burp-recheck-scan-graphql-<ver>.jar` — bản GraphQL
- `burp-recheck-scan-aura-<ver>.jar` — bản Aura

## Cài vào Burp

**Extensions → Installed → Add → Java** → chọn JAR của bản bạn cần. Có thể nạp cả 3 (mỗi bản
hiện một tab riêng: *Recheck Scan API*, *Recheck Scan GraphQL*, *Recheck Scan Aura*).

## Cấu trúc

```
src/main/java/com/example/
├── RecheckScanApiExtension.java   # REST (bản gốc)
├── DatabaseManager.java · SettingsPanel.java · PathParameterRule.java
├── graphql/                       # bản GraphQL (self-contained)
│   └── GraphQL*.java
└── aura/                          # bản Aura (self-contained)
    ├── RecheckScanAuraExtension.java
    ├── AuraActionExtractor.java · Json.java
    ├── AuraDatabaseManager.java · AuraSettingsPanel.java · PathParameterRule.java
```

## Credits

Bản gốc bởi [vn-ncvinh](https://github.com/vn-ncvinh). Các bản GraphQL và Aura mở rộng để
định danh đúng và không bỏ sót tham số cho từng loại API.
