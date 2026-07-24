# AKS audit parsing patterns — provenance & verification

How the parsing patterns used in our KQL detections (and the newsletter posts) were
derived, and how to re-verify them. The short version: the field shapes are not
guessed from samples — they are declared in the upstream Kubernetes audit API spec,
and every pattern was executed verbatim against a real Kusto engine before publishing.

## Where the schema comes from

`AKSAudit` and `AKSAuditAdmin` rows are Kubernetes `audit.k8s.io/v1 Event` objects
with fields mapped 1:1 to columns. Two authoritative references:

- **Upstream spec** (declares each field's type):
  <https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/>
- **Azure Monitor table reference** (column list and types as ingested):
  <https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksaudit>

Per the Azure reference the table has 24 columns, of which exactly 7 are `dynamic`.
Their shapes, fixed by the upstream type declarations:

| Column | Upstream type | Shape | Parse with |
|--------|---------------|-------|------------|
| `User` | `authentication/v1.UserInfo` (`username`, `uid`, `groups []string`) | dictionary (contains an array) | `tostring(User.username)`, `strcat_array(User.groups, ", ")` |
| `SourceIps` | `[]string` | array | `tostring(SourceIps[0])` |
| `ObjectRef` | `audit/v1.ObjectReference` | dictionary | `tostring(ObjectRef.resource)` etc. |
| `ResponseStatus` | `meta/v1.Status` | dictionary | `toint(ResponseStatus.code)` |
| `Annotations` | `map[string]string` (dotted keys) | dictionary | `tostring(Annotations["authorization.k8s.io/decision"])` |
| `RequestObject` | `runtime.Unknown` (full submitted object) | dictionary, arrays-of-dictionaries inside | `mv-apply` |
| `ResponseObject` | `runtime.Unknown` (full returned object) | dictionary, arrays-of-dictionaries inside | `mv-apply` |

## SourceIps ordering — and its trust boundary

The spec defines the ordering of `sourceIPs`: X-Forwarded-For header IPs first,
then X-Real-Ip, then the connection's remote address. XFF convention is
client-first, so `[0]` is the client. The spec adds, verbatim:

> All but the last IP can be arbitrarily set by the client.

Detection implication: with no proxy headers the list has one element — the real
TCP peer — and `[0]` is trustworthy. When proxy headers are present, `[0]` is the
*claimed* client; only the **last** element is verified by the API server.

## Known gaps in `RequestObject`

- It can be the literal string `"skipped-too-big-size-object"` when the object is
  too large; `mv-apply` over it then silently yields no rows.
- Container-walking queries must cover `spec.initContainers` (and
  `spec.ephemeralContainers`) as well as `spec.containers` — a privileged
  initContainer slips past a `spec.containers`-only query. Our shipped
  `detections/kql/privileged-pod.kql` handles this; simplified examples in posts
  may not.

## How to re-verify

**1. Shape probe against live data.** `gettype()` returns the runtime shape of a
dynamic value, so this proves the assumption across every ingested row — any
violating row shows up as its own bucket:

```kql
AKSAudit
| summarize rows = count()
    by SourceIps_shape = gettype(SourceIps),
       User_shape      = gettype(User),
       ip_count        = array_length(SourceIps)
```

**2. Execute the queries verbatim in a real Kusto engine.** Same mechanism as the
Tier 1 CI harness (`tools/detection-tester/kql_test.py`): shadow the table name
with a `let` datatable of fixture rows, then paste the query unmodified below it.
Because the `let` shadows the table, the exact published query runs against the
fixture — in the Kusto emulator, the [free ADX cluster](https://dataexplorer.azure.com/freecluster),
or the Log Analytics demo workspace. No AKS cluster needed:

```kql
let AKSAuditAdmin = datatable(
    Verb:string, RequestUri:string, User:dynamic, SourceIps:dynamic,
    ObjectRef:dynamic, ResponseStatus:dynamic, Annotations:dynamic,
    RequestObject:dynamic, ResponseObject:dynamic)
[
    "list", "/api/v1/secrets?limit=1000",
    dynamic({"username":"masterclient","uid":"abc-123","groups":["system:masters","system:authenticated"]}),
    dynamic(["203.0.113.50","10.244.0.7"]),
    dynamic({"resource":"secrets","apiVersion":"v1"}),
    dynamic({"code":200}),
    dynamic({"authorization.k8s.io/decision":"allow"}),
    dynamic(null), dynamic(null)
]
| extend TimeGenerated = now();
// paste the query under test here, unmodified
AKSAuditAdmin
| extend User_name = tostring(User.username), ClientIP = tostring(SourceIps[0])
```

The flattener and mv-apply queries from the "Only Seven Fields Need Parsing" post
were verified this way against the Kusto emulator
(`mcr.microsoft.com/azuredataexplorer/kustainer-linux`) — every projected cell
checked against expected values, including that `mv-apply` returned only the one
privileged container out of three and that fields absent from a row flatten to
empty string rather than erroring.
