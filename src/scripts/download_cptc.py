import gzip
from urllib.request import Request, urlopen


def main(teams=None):
    """
    Downloads the suricata_alert.json for the specified teams from CPTC'18
    :param teams: List of teams to download data from. Defaults to all teams
    """
    if teams is None:
        teams = [1, 2, 5, 7, 8, 9]

    for team in teams:
        req = Request(f"http://cptc.rit.edu/2018/t{team}/events/suricata_alert.json.gz")
        req.add_header('Accept-Encoding', 'gzip')
        response = urlopen(req)
        content = gzip.decompress(response.read())

        with open(f"../data/cptc_18/suricata_alert_t{team}.json", "wb+") as out:
            out.write(content)
            out.close()


if __name__ == '__main__':
    main()
