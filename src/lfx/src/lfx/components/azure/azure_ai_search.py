from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient

from langflow.custom import Component
from langflow.io import IntInput, Output, SecretStrInput, StrInput
from langflow.schema import Data


class AzureAISearchComponent(Component):
    display_name = "Azure AI Search"
    description = "Search Azure AI Search (formerly Cognitive Search) for documents and content"
    icon = "Azure"
    name = "AzureAISearch"

    inputs = [
        StrInput(
            name="search_endpoint",
            display_name="Search Endpoint",
            required=True,
            info="Your Azure AI Search endpoint (e.g., https://your-search-service.search.windows.net)",
        ),
        SecretStrInput(
            name="search_key", display_name="Search Key", required=True, info="Your Azure AI Search API key"
        ),
        StrInput(name="index_name", display_name="Index Name", required=True, info="Name of the search index to query"),
        StrInput(name="search_query", display_name="Search Query", required=True, info="The search query to execute"),
        IntInput(name="top_results", display_name="Top Results", value=5, info="Number of top results to return"),
        StrInput(
            name="select_fields",
            display_name="Select Fields",
            value="*",
            info="Comma-separated list of fields to return (use * for all fields)",
        ),
        StrInput(name="filter_query", display_name="Filter Query", value="", info="Optional OData filter expression"),
    ]

    outputs = [
        Output(display_name="Search Results", name="search_results", method="search_documents"),
        Output(display_name="Raw Response", name="raw_response", method="get_raw_response"),
    ]

    def search_documents(self) -> Data:
        """Search Azure AI Search and return results."""
        try:
            # Create search client
            credential = AzureKeyCredential(self.search_key)
            search_client = SearchClient(
                endpoint=self.search_endpoint, index_name=self.index_name, credential=credential
            )

            # Prepare search options
            select_fields = self.select_fields.split(",") if self.select_fields != "*" else None

            # Execute search
            results = search_client.search(
                search_text=self.search_query,
                top=self.top_results,
                select=select_fields,
                filter=self.filter_query if self.filter_query else None,
            )

            # Process results
            search_results = [dict(result) for result in results]

            self.status = f"Found {len(search_results)} results for query: '{self.search_query}'"

            return Data(
                data={
                    "results": search_results,
                    "query": self.search_query,
                    "total_results": len(search_results),
                    "index_name": self.index_name,
                }
            )

        except (ValueError, ConnectionError, TimeoutError) as e:
            self.status = f"Error searching Azure AI Search: {e!s}"
            return Data(data={"error": str(e)})

    def get_raw_response(self) -> Data:
        """Get raw search response for debugging."""
        try:
            credential = AzureKeyCredential(self.search_key)
            search_client = SearchClient(
                endpoint=self.search_endpoint, index_name=self.index_name, credential=credential
            )

            results = search_client.search(
                search_text=self.search_query,
                top=self.top_results,
                select=self.select_fields.split(",") if self.select_fields != "*" else None,
                filter=self.filter_query if self.filter_query else None,
            )

            raw_results = [dict(result) for result in results]

            return Data(
                data={
                    "raw_response": raw_results,
                    "query": self.search_query,
                    "endpoint": self.search_endpoint,
                    "index": self.index_name,
                }
            )

        except (ValueError, ConnectionError, TimeoutError) as e:
            return Data(data={"error": str(e)})
