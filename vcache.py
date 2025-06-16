import argparse
import requests
import httpx
import logging

def configure_logging(verbose):
    """Configures logging based on the verbose flag."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(levelname)s: %(message)s')

def scan_url(url, verbose):
    """Scans a given URL for potential web cache poisoning vulnerabilities."""
    logging.info(f"Scanning: {url}")
    try:
        response = requests.get(url, allow_redirects=False)

        # Check for cache-related headers
        cache_headers = {
            header: response.headers.get(header)
            for header in ['Cache-Control', 'Age', 'Pragma']
            if header in response.headers
        }

        if cache_headers:
            logging.info("Found cache-related headers:")
            for header, value in cache_headers.items():
                logging.info(f"  {header}: {value}")

            # Check for potentially influential headers not included in the cache key
            # (This is a simplified example, a real scanner would require more advanced analysis)
            for header, value in response.headers.items():
                if header.lower() not in ['cache-control', 'age', 'pragma', 'content-length', 'content-type'] and 'cache' not in header.lower():
                    logging.debug(f"  Potential influential header: {header}: {value}")

            # Example: Check for specific cache-poisoning indicators (highly simplified)
            if "poisoned_content" in response.text: # Replace with actual attack vector identification
                logging.warning("Potential web cache poisoning detected!")

        else:
            logging.info("No explicit cache-related headers found.")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error scanning {url}: {e}")

def main():
    print("\033[97m")

    parser = argparse.ArgumentParser(description="Web Cache Vulnerabilities")
    parser.add_argument("url", help="URL to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    configure_logging(args.verbose)
    scan_url(args.url, args.verbose)

if __name__ == "__main__":
    main()
