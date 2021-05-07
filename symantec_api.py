"""Used to pull events from symantec ATP using the API."""

from argparse import ArgumentParser
import sys
from json import dumps, dump
from base64 import b64encode
from multiprocessing import Pool
from datetime import datetime, timedelta
from yaml import load, FullLoader, scanner, parser as yaml_parser
from requests import post, exceptions as requests_exception
from urllib3 import disable_warnings, exceptions as urllib3_exception
from tqdm import tqdm


class API:
    """Make API calls and write events."""

    def __init__(self, api_creds, now_datetime_out, end_datetime_out, query):
        """Intialize variables."""
        self.api_creds = api_creds
        self.now_datetime_out = now_datetime_out
        self.end_datetime_out = end_datetime_out
        self.query = query

    def _api_call(self, server):
        """Make API calls to pull events."""

        def _api_auth(server):
            """Get access token for API calls."""
            disable_warnings(urllib3_exception.InsecureRequestWarning)
            url = f'https://{server["server"]}/atpapi/oauth2/tokens'
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f'Basic {server["encoded_auth"]}'
            }
            data = "grant_type=client_credentials&scope=customer"
            try:
                authorization_response = post(url, headers=headers, data=data, verify=False)
            except requests_exception.ConnectionError:
                print(f'Failed to connect to server: {server["server"]}')
                raise ConnectionError
            if authorization_response.status_code >= 200 and authorization_response.status_code <= 299:
                auth = authorization_response.json()
                return auth
            else:
                print(f'Autorization Failed on server: {server["server"]}')
                raise ConnectionError

        def _write_events_file(server, atp_events):
            """Write pulled events to file."""
            now_datetime = (datetime.utcnow()).strftime("%Y-%m-%d_T%H%M%S")
            with open(f'{now_datetime}_{str.replace(server["server"], ".", "-")}.json', "w+") as event_output:
                for event in atp_events:
                    dump(event, event_output)
                    event_output.write("\n")

        auth = _api_auth(server)
        url = f'https://{server["server"]}/atpapi/v2/events'
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth['access_token']}"
        }
        data = {
            "verb": "query",
            "query": self.query,
            "start_time": self.end_datetime_out,
            "end_time": self.now_datetime_out,
        }
        try:
            query_results = post(url, headers=headers, data=dumps(data), verify=False)
        except requests_exception.ConnectionError:
            print(f'Failed to connect to server: {server["server"]}')
            raise ConnectionError
        if query_results.status_code >= 200 and query_results.status_code <= 299:
            if int(query_results.json()["total"]) > 100:
                atp_events = query_results.json()["result"]
                prog_bar = tqdm(total=(int(query_results.json()["total"])), desc=f'{server["server"]}: ')
                prog_bar.update(100)
                try:
                    while query_results.json()["next"] is not None:
                        data["next"] = query_results.json()["next"]
                        query_results = post(url, headers=headers, data=dumps(data), verify=False)
                        if query_results.status_code >= 400 and query_results.status_code <= 499:
                            auth = _api_auth(server)
                            headers["Authorization"] = f"Bearer {auth['access_token']}"
                            query_results = post(url, headers=headers, data=dumps(data), verify=False)
                        atp_events = atp_events + query_results.json()["result"]
                        prog_bar.update(len(query_results.json()["result"]))
                    prog_bar.close()
                    print("")
                    _write_events_file(server, atp_events)
                except KeyboardInterrupt:
                    prog_bar.close()
                    return
                except KeyError:
                    _write_events_file(server, atp_events)
                    prog_bar.close()
                    raise StopIteration
                except requests_exception.ConnectionError:
                    print(f'Failed to pull events from server: {server["server"]}')
                    prog_bar.close()
                    raise ConnectionError
            else:
                prog_bar = tqdm(total=(int(query_results.json()["total"])), desc=f'{server["server"]}: ')
                prog_bar.update(len(query_results.json()["result"]))
                atp_events = query_results.json()["result"]
                prog_bar.close()
                print("")
                _write_events_file(server, atp_events)

        else:
            print(f'Failed to pull events from server: {server["server"]}')
            print(f'{query_results.json()["error"]} {query_results.json()["message"]}')
            print("")
            raise ConnectionError

    def get_logs(self):
        """Spawn the processes and map to servers to make API requests in parallel."""
        print("\nDepending on event total this my take some time. There is 1 api call for every 100 events.\n")
        try:
            p = Pool(len(self.api_creds))
            p.map(self._api_call, self.api_creds, 1)
            p.terminate()
            return True
        except KeyboardInterrupt:
            p.terminate()
            return False
        except ConnectionError:
            p.terminate()
            return False
        except StopIteration:
            print("Something went wrong. Events that were pulled have been written to file.")
            return False

def main():
    def _get_dates_and_creds(server, days, hours, date_time):
        """Calculate timerange and get credentials."""

        def _single_server(server):
            """Get credentials for single server passed from commandline arguments."""
            try:
                with open("servers.yaml", 'r') as servers_file:
                    try:
                        server_creds = load(servers_file, Loader=FullLoader)
                    except scanner.ScannerError as err:
                        print("\n\nThere is an issue with the servers.yaml file. Correct issue and try again.")
                        print(err)
                        print("\n\n")
                        sys.exit(1)
                    except yaml_parser.ParserError as err:
                        print("\n\nThere is an issue with the servers.yaml file. Correct issue and try again.")
                        print(err)
                        print("\n\n")
                        sys.exit(1)
                api_creds = []
                try:
                    credentials = server_creds[server]
                    server_creds = {
                        "server": server,
                        "encoded_auth": (b64encode(f'{credentials["client_id"]}:{credentials["client_secret"]}'.encode())).decode()
                    }
                except KeyError as err:
                    print(f"\n\ncheck your servers.yaml file. It is missing the {err} for {server}\n\n")
                    sys.exit(1)
                api_creds.append(server_creds)
                return api_creds
            except FileNotFoundError:
                print("\n\nPlease create a servers.yaml file.\n\n")
                sys.exit(1)

        def _all_servers():
            """Get credentials for all servers in servers.yaml file."""
            try:
                with open("servers.yaml", 'r') as servers_file:
                    try:
                        server_info = load(servers_file, Loader=FullLoader)
                    except scanner.ScannerError as err:
                        print("\n\nThere is an issue with the servers.yaml file. Correct issue and try again.")
                        print(err)
                        print("\n\n")
                        sys.exit(1)
                    except yaml_parser.ParserError as err:
                        print("\n\nThere is an issue with the servers.yaml file. Correct issue and try again.")
                        print(err)
                        print("\n\n")
                        sys.exit(1)
                try:
                    api_creds = []
                    for server in server_info:
                        credentials = server_info[server]
                        server_creds = {
                            "server": server,
                            "encoded_auth": (b64encode(f'{credentials["client_id"]}:{credentials["client_secret"]}'.encode())).decode()
                        }
                        api_creds.append(server_creds)
                    return api_creds
                except KeyError as err:
                    print(f"\n\ncheck your servers.yaml file. It is missing the {err} for {server}\n\n")
                    sys.exit(1)
            except FileNotFoundError:
                print("\n\nPlease create a servers.yaml file.\n\n")
                sys.exit(1)

        now_datetime_out = (date_time).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        end_datetime_out = (date_time - timedelta(days=days, hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if server:
            api_creds = _single_server(server)
        else:
            api_creds = _all_servers()
        return api_creds, now_datetime_out, end_datetime_out

    parser = ArgumentParser(description='Used to pull events from symantec ATP using the API')
    parser.add_argument("-q", metavar='Query', required=True, type=str, help="Required! The query to use. Make sure to encapsulate in quotes.")
    parser.add_argument("-s", metavar='Server', default="", type=str, help="Server IP. If none set will loop through all servers in servers.yaml file.")
    parser.add_argument("-d", metavar='Days', default=0, type=int, help="The amount of days you want. Max is 7, default is 0 (meaning now - 0 day).")
    parser.add_argument("-hr", metavar='Hours', default=0, type=int, help="The amount of hours you want. Default is 0 (meaning now - 0 hour).")
    parser.add_argument("-dt", metavar='Date Time', default=datetime.utcnow().strftime('%Y-%m-%d_%H:%M:%S'), type=lambda s: datetime.strptime(s, '%Y-%m-%d_%H:%M:%S'), help="Specific date and time (yyyy-mm-dd_hh:mm:ss), default is current utc time.")
    args = parser.parse_args()
    server = args.s
    query = args.q
    days = args.d
    hours = args.hr
    date_time = args.dt
    if days > 7 or hours > 168:
        print("Max date range allowed by API is 7 days or 168 hours.\nTry again with a shorter time range.")
        sys.exit(1)
    api = API(*_get_dates_and_creds(server, days, hours, date_time), query)
    complete = api.get_logs()
    if complete:
        print("COMPLETE")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
