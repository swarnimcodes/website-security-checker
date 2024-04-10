import difflib
import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List
from dotenv import load_dotenv

import requests
from requests import Response
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

__version__ = "v1.0.0"
sg_api_key = os.getenv("SENDGRID_API_KEY")
sg = SendGridAPIClient(sg_api_key)


http_observatory_base_url = "https://http-observatory.security.mozilla.org/api/v1/"
excel_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
excel_filename = f"output_{excel_timestamp}.xlsx"
MAX_RETRIES: int = 6
urlscanid_mapping = []


def custom_logger():
    def log(message: str, level: str):
        ts: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] --> [{level}] --> {message}")

    def debug(message: str):
        log(message, "DEBUG")

    def info(message: str):
        log(message, "INFO")

    def error(message: str):
        log(message, "ERROR")

    def critical(message: str):
        log(message, "CRITICAL")

    return debug, info, error, critical


def is_internet_accessible() -> bool:
    try:
        requests.get(url="https://www.google.com/", timeout=5)
        return True
    except Exception as err:
        error(f"`is_intenet_accessible` function failed: {err}")
        return False


def security_documentation(testcase: str):
    try:
        base_url = "https://infosec.mozilla.org/guidelines/web_security"
        tags = [
            "https",
            "http-strict-transport-security",
            "http-redirections",
            "http-public-key-pinning",
            "resource-loading",
            "content-security-policy",
            "contributejson",
            "cookies",
            "cross-origin-resource-sharing",
            "csrf-prevention",
            "referrer-policy",
            "robotstxt",
            "subresource-integrity",
            "version-history",
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
        ]
        selection = difflib.get_close_matches(testcase, tags)
        selection = selection[0]
        full_url = f"{base_url}#{selection}"
        return full_url
    except Exception as err:
        error(f"`security_documentation` function failed: {err}")


def send_email_for_failed_websites(website_list: List[str]):
    try:
        if len(website_list) < 1:
            return None
        global sg
        # to_email = ["swarnim335@gmail.com", "tech.support@iitms.co.in"]
        to_email = ["swarnim335@gmail.com"]
        from_email = "noreply@mastersofterp.co.in"
        curdate = datetime.now().strftime("%Y-%m-%d")
        subject = f"Website Vulnerabilities Summary - {curdate}"

        email_content = (
            f"This is a system generated email with regards to `website security vulnerabilities` dated `{curdate}`\n\n"
            f"The following websites could not be scanned by the system: {website_list}\n\n"
            "Regards,\n"
            "Website Vulnerabilities Checking System"
        )

        print(email_content)

        message = Mail(
            from_email=from_email,
            to_emails=to_email,
            subject=subject,
            plain_text_content=email_content,
        )

        sg_response: Any = sg.send(message)
        sg_sc = int(sg_response.status_code)
        if sg_sc // 100 == 2:
            info(f"Mail sent successfully to: {to_email}")
            return None
        else:
            error(f"Could not send mail to: {to_email}")
            return None

    except Exception as err:
        error(f"`send_failed_website_email` function failed: {err}")
        return None


def send_email(to_email: List[str], url: str, website_report: str):
    try:
        global sg
        # e = "swarnim335@gmail.com"
        # to_email.append(e)
        to_email = ["swarnim335@gmail.com"]
        from_email = "noreply@mastersofterp.co.in"
        curtime = datetime.now()
        timestamp = curtime.strftime("%Y-%m-%d %H:%M:%S")
        curdate = curtime.strftime("%Y-%m-%d")
        timestamp = datetime.now().strftime("%Y-%m-%d %H.%M.%S")
        subject = f"Website Security Vulnerabilities for `{url}` on `{timestamp}`"
        email_content = (
            (
                f"This is a system generated email with regards to website vulnerabilities dated `{curdate}`\n\n"
            )
            + website_report
            + ("Regards,\nWebsite Vulnerability Checking System")
        )

        # print(email_content)

        message = Mail(
            from_email=from_email,
            to_emails=to_email,
            subject=subject,
            plain_text_content=email_content,
        )

        # with open(excel_filename, "rb") as atf:
        #     # Read the file content and encode it to Base64
        #     file_content_base64 = base64.b64encode(atf.read()).decode("utf-8")

        # attachment = Attachment()
        # attachment.file_name = FileName(excel_filename)
        # attachment.file_content = FileContent(file_content_base64)
        # message.add_attachment(attachment)

        sg_response: Any = sg.send(message)
        sg_sc = int(sg_response.status_code)
        if sg_sc // 100 == 2:
            info(f"Mail sent successfully to: {to_email}")
            return None
        else:
            error(f"Could not send mail to: {to_email}")
            return None
    except Exception as err:
        error(f"`send_email` function failed: {err}")
        sg = SendGridAPIClient(sg_api_key)
        return None


def analyze(website: str, retries: int = 0) -> Dict[str, str] | None:
    try:
        info(f"Started analysis for: {website}")
        if retries >= MAX_RETRIES:
            return {"error": "MAX RETRIES EXCEEDED"}
        elif retries > 0:
            info(f"Retry Number: {retries}")

        url = f"{http_observatory_base_url}analyze?host={website}&hidden=false&rescan=true"
        data: Dict[str, Any] = {}

        try:
            http_observatory_response: Response = requests.post(url, timeout=100)
            http_observatory_response.raise_for_status()
        except requests.Timeout:
            return {"error": "TIMEOUT"}
        except requests.RequestException as e:
            return {"error": f"Request Exception: {e}"}

        if not http_observatory_response:
            return {"error": "NO RESPONSE"}
        status_code: int = http_observatory_response.status_code
        status_code_handler(status_code)

        try:
            data = http_observatory_response.json()
            if "state" in data:
                match data["state"]:
                    case "FINISHED":
                        info(f"State: {data['state']}\n")
                        if data["grade"] is not None:
                            return data
                        else:
                            analyze(website=website, retries=retries + 1)
                    case "PENDING", "RUNNING", _:
                        info(f"State: {data['state']}")
                        analyze(website=website, retries=retries + 1)
                    case "FAILED":
                        info(f"State: {data['state']}\n")
                        return data
                    case _:
                        info(f"State: {data['state']}\n")
                        return {"state": "UNKNOWN"}
        except requests.JSONDecodeError:
            error(f"Invalid JSON received for {website}")
            return {
                "error": f"Invalid JSON data received from mozilla http observatory for {website}"
            }
    except Exception as err:
        error(f"`analyze` function failed: {err}")
        return {"error": f"`analyze` function failed to analyze `{website}`: {err}"}


def scan_results(scanid: int):
    try:
        url = f"{http_observatory_base_url}getScanResults?scan={scanid}"
        info(f"Scan URL: {url}")
        data: Dict[str, Any] = {}
        scanner_response = requests.get(url)
        status_code = scanner_response.status_code
        status_code_handler(status_code)
        data = scanner_response.json()
        return data
    except Exception as err:
        error(f"`scan_results` function failed: {err}")


def read_json_config(filepath: str):
    try:
        if not os.path.exists(filepath):
            info(f"Config file not found: {filepath}")
            return None

        with open(file=filepath, mode="r") as cfg:
            json_config: List[Dict[str, Any]] = json.load(cfg)
        return json_config
    except Exception as err:
        error(f"`read_json_config` function failed: {str(err)}")
        return None


def status_code_handler(sc: int):
    match sc:
        case 503:
            critical("Mozilla Observatory is down. Please try again later.")
            sys.exit(1)
        case 400:
            info("Status Code: 400 - Bad Request")
            return
        case 404:
            info("Status Code: 404 - Resource Not Found")
            return
        case 429:
            error("Status Code: 429 - Request Limit Reached")
            sys.exit(1)
        case 500:
            info("Status Code: 500 - Internal Server Error")
            return
        case 200:
            info("Status Code: 200 - Request Successful.")
            pass
        case _:
            info(f"Unhandled status Code: {sc}")
            pass


def main() -> None:
    try:
        global __version__
        start_time = time.time()
        info(
            f"Website Vulnerability Identification System {__version__} has started execution."
        )
        config_filepath = (
            "/home/pythonadmin/python_apps/ms-website-security-checker/config.json"
        )
        json_config: List[Dict[str, Any]] | None = read_json_config(config_filepath)
        if not json_config:
            critical("Could not read JSON Config. Exiting...")
            sys.exit(1)

        error_websites: List[str] = []

        for object in json_config:
            if not is_internet_accessible():
                error("No internet Connection...")
                continue
            url = object["url"]
            emails = object["emails"]
            object["scan_id"] = -1
            website_analysis_data = analyze(url)
            if website_analysis_data is None:
                error(f"No analysis data found for: `{url}`. Skipping...")
                continue
            scan_id = website_analysis_data.get("scan_id", -1)
            grade = website_analysis_data.get("grade", "--")
            likelihood = website_analysis_data.get("likelihood_indicator", "--")
            num_test_passed = int(website_analysis_data.get("tests_passed", -1))
            num_test_failed = int(website_analysis_data.get("tests_failed", -1))
            object["scan_id"] = scan_id
            object["grade"] = grade
            object["risk_level"] = likelihood
            object["tests_passed"] = num_test_passed
            object["tests_failed"] = num_test_failed

        # print(json.dumps(json_config, indent=2))
        # Now we have a new config :D

        for object in json_config:
            if not is_internet_accessible():
                error("No internet Connection...")
                continue
            website_report = ""
            scan_id = int(object.get("scan_id", -1))
            grade = object.get("grade", "--")
            num_test_passed = object.get("tests_passed", -1)
            num_test_failed = object.get("tests_failed", -1)
            risk_level = object.get("risk_level")
            emails = object["emails"]

            url = object["url"]
            if scan_id < 0:
                error(f"Scan ID for {url} not found. Skipping...")
                continue
            website_analysis_data = scan_results(scanid=scan_id)
            if not website_analysis_data:
                error(f"No scan data found for: {url}")
                error_websites.append(url)
                continue
            # print(f"Test Results for URL: {url}:")
            # print(f"Grade: {grade}")
            # print(f"Tests Passed: {num_test_passed}")
            # print(f"Tests Failed: {num_test_failed}")
            # print(f"Total Tests: {num_test_passed+num_test_failed}\n")
            if num_test_failed > 0:
                website_report += f"Website Vulnerability Report for: `{url}`\n"
                website_report += f"\tGrade: {grade}\n"
                website_report += f"\tSecurity Risk Level: {risk_level}\n"
                website_report += f"\tTests Passed: {num_test_passed}\n"
                website_report += f"\tTests Failed: {num_test_failed}\n\n"
                website_report += "\tFailed Tests:\n"

            # print("All Test Details:")
            for test in website_analysis_data:
                test_data: Dict[str, Any] | None = website_analysis_data.get(test)
                if test_data is None:
                    error(f"No data for test: {test_data}. Continuing to next test...")
                    continue
                test_name = str(test).upper()
                # print(f"\tTest: {test_name}")
                test_passed = test_data.get("pass", "")
                # print(f"\t\tTest Status: {'PASSED' if test_passed else 'FAILED'}")
                reason = test_data.get("score_description", "")
                # print(f"\t\tReason: {reason}")
                score_modifier = test_data.get("score_modifier", 0)
                # print(f"\t\tScore Modifier: {score_modifier}")
                helpdoc = security_documentation(test)
                # print(f"\t\tHelp Documentation: {helpdoc}")
                if not test_passed and num_test_failed > 0:
                    website_report += f"\t\tTest: {test_name}\n"
                    website_report += f"\t\t\tReason: {reason}\n"
                    website_report += f"\t\t\tScore Modifier: {score_modifier}\n"
                    website_report += f"\t\t\tHelp Documentation: {helpdoc}\n\n"
                # print()
            # print(website_report)
            if num_test_failed > 0:
                send_email(to_email=emails, url=url, website_report=website_report)
        end_time = time.time()

        elapsed_time = end_time - start_time

        info(
            f"The following websites could not scanned by the system: {error_websites}"
        )
        send_email_for_failed_websites(website_list=error_websites)

        info(f"System Execution took: {elapsed_time:.2f} seconds")

    except Exception as err:
        critical(f"`main` function failed: {err}")


if __name__ == "__main__":
    debug, info, error, critical = custom_logger()
    main()
