#CRAWCISCAN

import requests
from flask import Flask, render_template, request
import flask
import scanner
import json
crawciscan = Flask(__name__)
@crawciscan.route("/",methods=['POST'])
def scanthesite():
    target_url = str(request.form['site'])
    links_to_ignore = [""]
    data_dict = {"username": "admin", "password": "password", "Login": "submit"}
    vuln_scanner = scanner.Scanner(target_url, links_to_ignore)
    vuln_scanner.crawl()
    output = vuln_scanner.run_scanner()
    final = str(output)
    with open('test.json', 'w') as file:
        json.dump(output, file)
    final3 = json.dumps(final, indent=2)
    print(final3)
    return final3
if __name__ == "__main__":
    crawciscan.run(debug=True)

