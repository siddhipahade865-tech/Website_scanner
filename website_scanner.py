import requests


# Check if the website is reachable
def check_website(url):
    try:
        response = requests.get(url, timeout=5)
        return response
    except requests.exceptions.RequestException:
        return None


# Check if HTTPS is being used
def check_https(url):
    if url.startswith("https://"):
        return True
    return False


# Check for important security headers
def check_security_headers(headers):
    security_headers = {
        "Content-Security-Policy": "Protects against XSS attacks",
        "X-Frame-Options": "Protects against clickjacking",
        "Strict-Transport-Security": "Forces HTTPS connections",
        "X-Content-Type-Options": "Prevents MIME-type sniffing"
    }

    results = {}

    for header in security_headers:
        if header in headers:
            results[header] = "Present"
        else:
            results[header] = "Missing"

    return results


# Print the scan report
def print_report(url, response):
    print("\n" + "=" * 50)
    print("       WEBSITE VULNERABILITY SCANNER")
    print("=" * 50)

    print(f"\nWebsite URL      : {url}")
    print(f"Status Code      : {response.status_code}")

    # HTTPS Status
    if check_https(url):
        print("HTTPS Enabled    : Yes")
    else:
        print("HTTPS Enabled    : No")

    # Server Information
    server = response.headers.get("Server", "Not Disclosed")
    print(f"Server Header    : {server}")

    # Security Header Check
    print("\nSecurity Headers:")
    header_results = check_security_headers(response.headers)

    for header, status in header_results.items():
        print(f"- {header}: {status}")

    # Recommendations
    print("\nRecommendations:")
    missing_found = False

    for header, status in header_results.items():
        if status == "Missing":
            print(f"- Consider adding {header}.")
            missing_found = True

    if not check_https(url):
        print("- Use HTTPS to secure communication.")
        missing_found = True

    if not missing_found:
        print("- No basic issues detected. Good security practices observed.")

    print("\nScan completed successfully.")
    print("=" * 50)


# Main Program
def main():
    print("=" * 50)
    print("      PYTHON WEBSITE VULNERABILITY SCANNER")
    print("=" * 50)

    while True:
        website = input("\nEnter website URL (include http:// or https://): ").strip()

        response = check_website(website)

        if response:
            print("\nScanning website...")
            print_report(website, response)
        else:
            print("\nUnable to connect to the website.")
            print("Please check the URL and your internet connection.")

        choice = input("\nDo you want to scan another website? (y/n): ").lower()
        if choice != "y":
            print("\nThank you for using the Website Vulnerability Scanner.")
            break


# Run the program
if __name__ == "__main__":
    main()