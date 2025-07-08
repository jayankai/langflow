// Utility to handle iframe token from URL parameters and parent window communication

let iframeToken: string | null = null;

// Get token from URL parameters (primary method)
const urlParams = new URLSearchParams(window.location.search);
const tokenFromUrl = urlParams.get('token');
if (tokenFromUrl) {
  iframeToken = tokenFromUrl;
  console.log("Iframe token loaded from URL parameters");
}

// Listen for token from parent window (backup method)
window.addEventListener("message", (event) => {
  if (event.data?.type === "SET_IFRAME_TOKEN") {
    iframeToken = event.data.token;
    console.log("Iframe token received from parent window");
  }
});

// Function to get the current iframe token
export function getIframeToken(): string | null {
  return iframeToken;
}

// Function to set the iframe token (for testing or direct setting)
export function setIframeToken(token: string): void {
  iframeToken = token;
}

// Function to clear the iframe token
export function clearIframeToken(): void {
  iframeToken = null;
}
