import requests
import gzip
import shutil
from urllib.request import Request, urlopen


def main(teams=None):
    """
    Downloads and decompresses the suricata alerts from CPTC'18.

    :param teams: List of teams to download. Default all teams with a submission
    :param data_dir: Directory to store the data in
    """
    if teams is None:
        teams = [1, 2, 5, 7, 8, 9]

    for team in teams:
        print(f"Downloading data for team {team}")
        response = requests.get(f"http://cptc.rit.edu/2018/t{team}/events/suricata_alert.json.gz")

        if not response.ok:
            raise RuntimeError("Error in dowloading data")

        print(response.content)

        print("Writing")

        with open(f"../data/cptc_18/suricata_alert_t{team}.json", "wb+") as f:
            response.raw.decode_content = True  # just in case transport encoding was applied
            gzip_file = gzip.GzipFile(fileobj=response.raw)
            shutil.copyfileobj(gzip_file, f)
            f.close()
        print("Done with team")


def main2(teams=None):
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
    main2()
