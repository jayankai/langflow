import base64
import json
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any
from uuid import UUID

import pandas as pd
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient

from langflow.custom import Component
from langflow.io import BoolInput, HandleInput, IntInput, Output, SecretStrInput, StrInput
from langflow.schema import Data


class AzureSearchUpserterComponent(Component):
    display_name = "Azure Search Upserter"
    description = "Upsert documents into Azure Cognitive Search from DB/records output"
    icon = "Azure"
    name = "AzureSearchUpserter"

    # ---------- Inputs ----------
    inputs = [
        # Azure Search
        StrInput(
            name="search_endpoint",
            display_name="Search Endpoint",
            required=True,
            info="e.g., https://<service>.search.windows.net",
        ),
        SecretStrInput(name="search_key", display_name="Search Key", required=True),
        StrInput(name="index_name", display_name="Index Name", required=True),
        # Mapping
        StrInput(name="id_field", display_name="ID Field", value="id", info="Key field defined in your index"),
        StrInput(
            name="content_field",
            display_name="Content Field",
            value="content",
            info="Searchable text field (for BM25/hybrid)",
        ),
        StrInput(
            name="vector_field",
            display_name="Vector Field",
            value="content_vector",
            info="Vector field (Collection(Edm.Single))",
        ),
        # JSON handling
        StrInput(name="json_mode", display_name="JSON Mode", value="string", info="One of: string | flatten | object"),
        StrInput(
            name="flatten_prefix",
            display_name="Flatten Prefix",
            value="meta",
            info="Used when json_mode = flatten (fields become 'meta.foo.bar')",
        ),
        IntInput(
            name="flatten_max_depth", display_name="Flatten Max Depth", value=2, info="Max depth for flatten mode"
        ),
        # Control
        IntInput(name="batch_size", display_name="Batch Size", value=100),
        BoolInput(
            name="delete_existing",
            display_name="Delete All Existing First",
            value=False,
            info="Deletes all docs (iterates over keys) before upserting",
        ),
        BoolInput(name="auto_generate_ids", display_name="Auto Generate IDs", value=True),
        BoolInput(name="skip_errors", display_name="Skip Errors", value=True),
        # Upstream data
        HandleInput(
            name="input_data",
            display_name="Input Data",
            input_types=["Data", "DataFrame", "Message", "Document", "Text"],
            required=True,
            info="Connect your DB/query node or any record-emitting node here",
        ),
    ]

    # ---------- Outputs ----------
    outputs = [
        Output(display_name="Result", name="result", method="run"),
        Output(display_name="Sample (First 3)", name="sample", method="get_sample"),
    ]

    # ---------- Helpers ----------
    def _flatten_dict(self, obj: dict[str, Any], prefix: str, max_depth: int, depth: int = 0) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if depth >= max_depth:
            # Stop here, serialize the rest
            out[prefix] = json.dumps(obj, ensure_ascii=False)
            return out
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                out.update(self._flatten_dict(v, key, max_depth, depth + 1))
            else:
                out[key] = v
        return out

    def _to_search_primitive(self, key: str, value: Any) -> Any:
        """Convert Python/DB types to Azure Search-friendly values.

        Convert Python/DB types to Azure Search-friendly values,
        preserving vector field as list[float].
        """
        # Preserve vector field
        if key == getattr(self, "vector_field", "content_vector"):
            # Expect list[float]; if Decimal/str, coerce best-effort
            if isinstance(value, list | tuple):
                vec = []
                for x in value:
                    if isinstance(x, int | float | Decimal):
                        vec.append(float(x))
                    elif isinstance(x, str):
                        try:
                            vec.append(float(x))
                        except (ValueError, TypeError):
                            # skip bad values
                            continue
                    else:
                        # skip unsupported element types
                        continue
                return vec
            # If vector is provided as JSON string
            if isinstance(value, str):
                try:
                    arr = json.loads(value)
                    if isinstance(arr, list):
                        return [float(x) for x in arr]
                except (ValueError, TypeError):
                    pass
            return value  # let it fail loudly upstream if schema mismatches

        # None → omit at caller
        if value is None:
            return None

        # Simple primitives
        if isinstance(value, bool | int | float | str):
            return value

        # Decimal → float
        if isinstance(value, Decimal):
            return float(value)

        # UUID → str
        if isinstance(value, UUID):
            return str(value)

        if isinstance(value, datetime):
            return value.isoformat(timespec="milliseconds") + "Z"
        if isinstance(value, date):
            return value.isoformat()
        if isinstance(value, time):
            return value.strftime("%H:%M:%S")

        # bytes/bytearray → base64 string
        if isinstance(value, bytes | bytearray):
            return base64.b64encode(value).decode("ascii")

        # Lists/Tuples → try to convert elements recursively to strings/numbers/bools
        if isinstance(value, list | tuple):
            converted = []
            for item in value:
                prim = self._to_search_primitive(key, item)
                # Azure collections must be homogenous primitives;
                # coerce complex leftovers to JSON strings.
                if isinstance(prim, dict | list):
                    prim = json.dumps(prim, ensure_ascii=False)
                converted.append(prim)
            return converted

        # Dicts: defer handling to caller (respect json_mode)
        if isinstance(value, dict):
            return value

        # Fallback: stringify
        return str(value)

    def _normalize_records(self, raw: Any) -> list[dict[str, Any]]:
        """Accepts DataFrame, list[dict], list[Document], Data{data=...}, str, dict, etc.

        Accepts DataFrame, list[dict], list[Document], Data{data=...}, str, dict, etc.
        Returns a list[dict].
        """
        # LangChain Document(s)
        if isinstance(raw, list) and all(hasattr(x, "page_content") for x in raw):
            return [
                {
                    "content": x.page_content,
                    **({"metadata": getattr(x, "metadata", {})} if getattr(x, "metadata", None) else {}),
                }
                for x in raw
            ]

        # pandas DataFrame
        if isinstance(raw, pd.DataFrame):
            return raw.to_dict(orient="records")

        # Langflow Data wrapper
        if hasattr(raw, "data"):
            payload = raw.data
            if isinstance(payload, pd.DataFrame):
                return payload.to_dict(orient="records")
            if isinstance(payload, list):
                return payload
            if isinstance(payload, dict):
                # Common shapes: {"results": [...]}, {"data": [...]}, {"documents": [...]}
                for k in ("results", "data", "documents", "rows"):
                    if k in payload and isinstance(payload[k], list):
                        return payload[k]
                return [payload]

        # list of dicts already
        if isinstance(raw, list) and (len(raw) == 0 or isinstance(raw[0], dict)):
            return raw

        # single dict
        if isinstance(raw, dict):
            return [raw]

        # single string → wrap
        if isinstance(raw, str):
            return [{"content": raw}]

        # Fallback: try coercion
        try:
            return [dict(raw)]
        except (TypeError, ValueError) as e:
            msg = f"Unsupported upstream data type: {type(raw)}"
            raise ValueError(msg) from e

    def _prepare_for_index(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Applies type conversions and JSON handling policy.

        Applies type conversions and JSON handling policy.
        Ensures id/content presence; preserves vector field.
        """
        out: list[dict[str, Any]] = []
        json_mode = (self.json_mode or "string").strip().lower()
        id_field = getattr(self, "id_field", "id")
        content_field = getattr(self, "content_field", "content")
        vector_field = getattr(self, "vector_field", "content_vector")

        for i, rec in enumerate(records):
            record = {"content": str(rec)} if not isinstance(rec, dict) else rec

            # Make a shallow copy to avoid mutating upstream
            doc: dict[str, Any] = {}

            # First pass: convert primitives and keep dicts for JSON handling stage
            dict_buffer: dict[str, dict[str, Any]] = {}  # field -> dict value (to process by mode later)

            for k, v in record.items():
                if v is None:
                    continue

                prim = self._to_search_primitive(k, v)

                # defer dicts for json handling
                if isinstance(prim, dict):
                    dict_buffer[k] = prim
                    continue

                # if prim is None (from vector coercion edge cases), skip
                if prim is None:
                    continue

                doc[k] = prim

            # JSON handling policy
            if json_mode == "object":
                # Keep dicts as-is (requires complex fields in the Azure index schema)
                doc.update(dict_buffer)
            elif json_mode == "flatten":
                prefix = (self.flatten_prefix or "meta").strip(".")
                maxd = int(self.flatten_max_depth or 2)
                for k, v in dict_buffer.items():
                    flat = self._flatten_dict(v, f"{prefix}.{k}" if prefix else k, maxd)
                    # Convert flattened values to search primitives
                    for fk, fv in flat.items():
                        doc[fk] = self._to_search_primitive(fk, fv)
            else:
                # "string" (default): serialize dicts to JSON strings
                for k, v in dict_buffer.items():
                    doc[k] = json.dumps(v, ensure_ascii=False)

            # Ensure id
            if id_field not in doc or doc[id_field] in (None, ""):
                if self.auto_generate_ids:
                    doc[id_field] = f"doc_{i}"
                else:
                    msg = f"Missing required id_field '{id_field}' on record {i}"
                    raise ValueError(msg)

            # Ensure content (use first string field if missing)
            if content_field not in doc or doc[content_field] in (None, ""):
                # Try common text fields
                for candidate in ("text", "content", "description", "title", "name"):
                    if candidate in record and isinstance(record[candidate], str) and record[candidate].strip():
                        doc[content_field] = record[candidate]
                        break
                else:
                    # fallback: stringify a non-id field
                    for k, v in record.items():
                        if k != id_field and isinstance(v, str) and v.strip():
                            doc[content_field] = v
                            break
                    else:
                        doc[content_field] = ""

            out.append(doc)

            # Optional sanity: ensure vector field (if present) is list[float] or absent
            if vector_field in doc and not (
                isinstance(doc[vector_field], list) and all(isinstance(x, int | float) for x in doc[vector_field])
            ):
                msg = f"Vector field '{vector_field}' must be a list of numbers"
                raise ValueError(msg)

        return out

    def _paginate_delete_all(self, client: SearchClient, key_field: str, page_size: int = 1000):
        """Safely deletes all documents by paging over keys."""
        # Note: select on key; '*' search to enumerate docs
        results = client.search(search_text="*", select=key_field, top=page_size)
        batch = []
        count_in_batch = 0
        for doc in results:
            batch.append({key_field: doc[key_field]})
            count_in_batch += 1
            if count_in_batch >= page_size:
                client.delete_documents(documents=batch)
                batch = []
                count_in_batch = 0
        if batch:
            client.delete_documents(documents=batch)

    # ---------- Node methods ----------
    def run(self) -> Data:
        try:
            if not self.input_data:
                return Data(data={"error": "No input_data connected"})

            # 1) Normalize upstream data to list[dict]
            records = self._normalize_records(self.input_data)

            if not records:
                return Data(data={"error": "No records to index"})

            # 2) Prepare for index (types & JSON policy)
            docs = self._prepare_for_index(records)

            # 3) Client
            client = SearchClient(
                endpoint=self.search_endpoint,
                index_name=self.index_name,
                credential=AzureKeyCredential(self.search_key),
            )

            # 4) Optional delete all
            if self.delete_existing:
                self.log("Deleting all existing documents...")
                try:
                    self._paginate_delete_all(client, key_field=self.id_field, page_size=1000)
                except Exception as e:
                    # Not fatal if user prefers to skip errors
                    if self.skip_errors:
                        self.log(f"Warning during delete_existing: {e}")
                    else:
                        raise

            # 5) Batch upload
            total = len(docs)
            bs = max(1, int(self.batch_size or 100))
            succeeded = 0
            failed: list[dict[str, Any]] = []

            for start in range(0, total, bs):
                batch = docs[start : start + bs]
                try:
                    results = client.upload_documents(documents=batch)
                    for r in results:
                        if r.succeeded:
                            succeeded += 1
                        else:
                            failed.append({"key": r.key, "error": r.error_message})
                except Exception as e:
                    if self.skip_errors:
                        failed.append({"batch_start": start, "error": str(e)})
                        continue
                    raise

            status = f"Indexed {succeeded}/{total} documents; failed={len(failed)}"
            self.status = status
            return Data(
                data={
                    "indexed": succeeded,
                    "total": total,
                    "failed": failed,
                    "index": self.index_name,
                    "status": status,
                }
            )

        except (ValueError, ConnectionError, TimeoutError) as e:
            self.status = f"Error: {e}"
            return Data(data={"error": str(e)})

    def get_sample(self) -> Data:
        try:
            if not self.input_data:
                return Data(data={"error": "No input_data connected"})
            recs = self._normalize_records(self.input_data)
            docs = self._prepare_for_index(recs[:3])
            return Data(data={"sample": docs, "count": len(docs)})
        except (ValueError, ConnectionError, TimeoutError) as e:
            return Data(data={"error": str(e)})

    def _format_datetime_for_azure(self, dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
