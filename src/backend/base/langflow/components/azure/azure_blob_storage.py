from azure.storage.blob import BlobServiceClient

from langflow.custom import Component
from langflow.io import BoolInput, Output, StrInput
from langflow.schema import Data


class AzureBlobStorageComponent(Component):
    display_name = "Azure Blob Storage"
    description = "Read and write files to Azure Blob Storage"
    icon = "Azure"
    name = "AzureBlobStorage"

    inputs = [
        StrInput(
            name="connection_string",
            display_name="Connection String",
            required=True,
            info="Azure Storage connection string",
        ),
        StrInput(
            name="container_name", display_name="Container Name", required=True, info="Name of the blob container"
        ),
        StrInput(name="blob_name", display_name="Blob Name", required=True, info="Name of the blob to read or write"),
        StrInput(
            name="content", display_name="Content", value="", info="Content to write to blob (for write operations)"
        ),
        BoolInput(
            name="is_write_operation",
            display_name="Is Write Operation",
            value=False,
            info="Set to True for write operations, False for read operations",
        ),
    ]

    outputs = [
        Output(display_name="Blob Content", name="blob_content", method="get_blob_content"),
        Output(display_name="Blob List", name="blob_list", method="list_blobs"),
        Output(display_name="Operation Result", name="operation_result", method="perform_operation"),
    ]

    def get_blob_content(self) -> Data:
        """Read content from Azure Blob Storage."""
        try:
            blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
            blob_client = blob_service_client.get_blob_client(container=self.container_name, blob=self.blob_name)

            # Download blob content
            blob_data = blob_client.download_blob()
            content = blob_data.readall().decode("utf-8")

            self.status = f"Successfully read blob: {self.blob_name}"

            return Data(
                data={
                    "content": content,
                    "blob_name": self.blob_name,
                    "container_name": self.container_name,
                    "size_bytes": len(content.encode("utf-8")),
                }
            )

        except (ValueError, ConnectionError, TimeoutError) as e:
            self.status = f"Error reading blob: {e!s}"
            return Data(data={"error": str(e)})

    def list_blobs(self) -> Data:
        """List all blobs in the container."""
        try:
            blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
            container_client = blob_service_client.get_container_client(self.container_name)

            blobs = [
                {
                    "name": blob.name,
                    "size": blob.size,
                    "last_modified": blob.last_modified.isoformat() if blob.last_modified else None,
                    "content_type": blob.content_settings.content_type,
                }
                for blob in container_client.list_blobs()
            ]

            self.status = f"Found {len(blobs)} blobs in container: {self.container_name}"

            return Data(data={"blobs": blobs, "container_name": self.container_name, "total_blobs": len(blobs)})

        except (ValueError, ConnectionError, TimeoutError) as e:
            self.status = f"Error listing blobs: {e!s}"
            return Data(data={"error": str(e)})

    def perform_operation(self) -> Data:
        """Perform read or write operation based on is_write_operation flag."""
        try:
            blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
            blob_client = blob_service_client.get_blob_client(container=self.container_name, blob=self.blob_name)

            if self.is_write_operation:
                # Write operation
                content_bytes = self.content.encode("utf-8")
                blob_client.upload_blob(content_bytes, overwrite=True)

                self.status = f"Successfully wrote blob: {self.blob_name}"

                return Data(
                    data={
                        "operation": "write",
                        "blob_name": self.blob_name,
                        "container_name": self.container_name,
                        "size_bytes": len(content_bytes),
                        "success": True,
                    }
                )
            # Read operation
            blob_data = blob_client.download_blob()
            content = blob_data.readall().decode("utf-8")

            self.status = f"Successfully read blob: {self.blob_name}"

            return Data(
                data={
                    "operation": "read",
                    "content": content,
                    "blob_name": self.blob_name,
                    "container_name": self.container_name,
                    "size_bytes": len(content.encode("utf-8")),
                    "success": True,
                }
            )

        except (ValueError, ConnectionError, TimeoutError) as e:
            self.status = f"Error performing operation: {e!s}"
            return Data(data={"error": str(e)})
