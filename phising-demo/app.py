from flask import Flask, render_template, request
import re
import socket
import requests
import whois
import dns.resolver
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime, timezone
import joblib
import socket, re, requests, tldextract
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import numpy as np
import ipaddress


app = Flask(__name__)
model_log = joblib.load("./static/logistic_url_model.pkl")
model_forest = joblib.load("./static/forest_url_model.pkl")
model_svm = joblib.load('./static/svm.pkl')
FEATURE_ORDER = [
 'UsingIP','LongURL','ShortURL','Symbol@','Redirecting//','PrefixSuffix-',
 'SubDomains','HTTPS','DomainRegLen','Favicon','NonStdPort','HTTPSDomainURL',
 'RequestURL','AnchorURL','LinksInScriptTags','ServerFormHandler','InfoEmail',
 'AbnormalURL','WebsiteForwarding','StatusBarCust','DisableRightClick',
 'UsingPopupWindow','IframeRedirection','AgeOfDomain','DNSRecording',
 'WebsiteTraffic','PageRank','GoogleIndex','LinksPointingToPage','StatsReport'
]

def check_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation = domain_info.creation_date

        if isinstance(creation, list):
            creation = next((c for c in creation if c), None)

        if not creation:
            return 1

        if creation.tzinfo:
            today = datetime.now(timezone.utc)
        else:
            today = datetime.now()

        age_days = (today - creation).days

        return -1 if age_days >= 180 else 1   

    except:
        return 1

def get_domain_reg_len(domain):
    try:
        domain_info = whois.whois(domain)
        creation = domain_info.creation_date
        expiration = domain_info.expiration_date

        if isinstance(creation, list):
            creation = next((c for c in creation if c), None)

        if isinstance(expiration, list):
            expiration = next((e for e in expiration if e), None)

        if not creation or not expiration:
            return 1

        age = (expiration - creation).days

        return -1 if age >= 365 else 1

    except:
        return 1


def ml_predict(url, model_type="forest"):
    features = extract_features(url)
    X = np.array([[features[f] for f in FEATURE_ORDER]])

    model = model_log if model_type == "logistic"  else model_forest if model_type == "forest" else model_svm

    probs = model.predict_proba(X)[0]
    classes = model.classes_

    prob_dict = dict(zip(classes, probs))

    phishing_prob = prob_dict.get(1, 0.0)
    legit_prob = prob_dict.get(-1, 0.0)

    pred = model.predict(X)[0]

    if pred == 1:
        label = "Phishing (Độc hại)"
        prob = phishing_prob
    else:
        label = "Legitimate (An toàn)"
        prob = legit_prob

    return label, float(prob)


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

import ipaddress

def extract_features(url):
    url = normalize_url(url)
    features = {
        'UsingIP': 1, 'LongURL':1, 'ShortURL': 1, 'Symbol@': 1,
        'Redirecting//': 1, 'PrefixSuffix-': 1, 'SubDomains': 1,
        'HTTPS': 1, 'DomainRegLen': 1, 'Favicon': 1,
        'NonStdPort': 1, 'HTTPSDomainURL': 1, 'RequestURL': 1,
        'AnchorURL': 1, 'LinksInScriptTags': 1, 'ServerFormHandler': 1,
        'InfoEmail': 1, 'AbnormalURL': 1, 'WebsiteForwarding': 1,
        'StatusBarCust': 1, 'DisableRightClick': 1,
        'UsingPopupWindow': 1, 'IframeRedirection': 1,
        'AgeOfDomain': 1, 'DNSRecording': 1, 'WebsiteTraffic': 1,
        'PageRank': -1, 'GoogleIndex': -1, 'LinksPointingToPage': -1,
        'StatsReport': -1
    }

    domain_info = tldextract.extract(url)
    domain = domain_info.domain + "." + domain_info.suffix
    parsed = urlparse(url)

    # ========== 1. UsingIP ==========
    try:
        ipaddress.ip_address(parsed.hostname)
        features["UsingIP"] = 1
    except:
        features["UsingIP"] = -1
    if len(url) < 54:
        features["LongURL"] = -1
    elif 54 <= len(url) <= 75:
        features["LongURL"] = 0
    else:
        features["LongURL"] = 1

    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]
    features["ShortURL"] = 1 if any(x in url for x in shorteners) else -1
    features["Symbol@"] = 1 if "@" in url else -1
    features["Redirecting//"] = 1 if url.rfind("//") > 6 else -1
    features["PrefixSuffix-"] = 1 if "-" in domain else -1

    # ========== 7. SubDomains ==========
    dots = domain.count(".")
    if dots <= 1:
        features["SubDomains"] = -1
    elif dots == 2:
        features["SubDomains"] = 0
    else:
        features["SubDomains"] = 1
    features["HTTPS"] = -1 if parsed.scheme == "https" else 1
    features["DomainRegLen"] = get_domain_reg_len(domain)
    features["NonStdPort"] = 1 if parsed.port not in [80, 443] else -1
    features["HTTPSDomainURL"] = -1 if "https" in domain else 1
    try:
        r = requests.get(url, timeout=7)
        soup = BeautifulSoup(r.text, "html.parser")
        favicon = soup.find("link", rel=re.compile("icon", re.I))
        if favicon and favicon.get("href"):
            features["Favicon"] = 1 if domain not in favicon.get("href") else -1
        imgs = soup.find_all("img", src=True)
        ext = [i for i in imgs if domain not in i["src"]]
        ratio = len(ext) / max(1, len(imgs))
        features["RequestURL"] = 1 if ratio > 0.5 else 0 if ratio > 0.2 else -1
        links = soup.find_all("a", href=True)
        unsafe = [a for a in links if domain not in a["href"]]
        ratio = len(unsafe) / max(1, len(links))
        features["AnchorURL"] = 1 if ratio > 0.5 else 0 if ratio > 0.2 else -1
        scripts = soup.find_all("script", src=True)
        ext_scripts = [s for s in scripts if domain not in s["src"]]
        features["LinksInScriptTags"] = 1 if ext_scripts else -1
        forms = soup.find_all("form", action=True)
        abnormal = [f for f in forms if domain not in f["action"]]
        features["ServerFormHandler"] = 1 if abnormal else -1
        features["InfoEmail"] = 1 if "mailto:" in r.text.lower() else -1
        features["AbnormalURL"] = 1 if domain not in url else -1
        if len(r.history) == 0:
            features["WebsiteForwarding"] = -1
        elif len(r.history) == 1:
            features["WebsiteForwarding"] = 0
        else:
            features["WebsiteForwarding"] = 1
        features["StatusBarCust"] = 1 if "onmouseover" in r.text.lower() else -1
        features["DisableRightClick"] = 1 if "event.button==2" in r.text.lower() else -1
        features["UsingPopupWindow"] = 1 if "window.open" in r.text.lower() else -1
        features["IframeRedirection"] = 1 if soup.find("iframe") else -1
    except:
        features['PageRank'] = 1
        features['GoogleIndex'] = 1
        features['LinksPointingToPage'] = 1
        features['StatsReport'] = 1
    features["AgeOfDomain"] = check_domain_age(domain)
    try:
        dns.resolver.resolve(domain, "A")
        features["DNSRecording"] = -1
    except:
        features["DNSRecording"] = 1

    return features


@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    probability = None
    url_input = ""
    selected_model = "forest"

    selected_mode = request.form.get("mode", "url")
    feature_values = {}

    if request.method == "POST":
        selected_model = request.form.get("model", "forest")

        if selected_mode == "url":

            url_input = request.form.get("url", "").strip()
            if url_input:
                prediction, probability = ml_predict(url_input, selected_model)

   
        elif selected_mode == "manual":
            for field in FEATURE_ORDER:
                raw_value = request.form.get(f"f_{field}", None)

                if raw_value is None:
                    feature_values[field] = 0
                else:
                    try:
                        feature_values[field] = int(float(raw_value))
                    except:
                        feature_values[field] = 0

            X = np.array([[feature_values[f] for f in FEATURE_ORDER]])

            if selected_model == "logistic":
                model = model_log
            elif selected_model == "forest":
                model = model_forest
            else:
                model = model_svm

            pred_class = model.predict(X)[0]
            proba = model.predict_proba(X)[0]

            prob_phishing = proba[list(model.classes_).index(1)]
            prob_legit = proba[list(model.classes_).index(-1)]

            if pred_class == 1:
                prediction = "Phishing (Độc hại)"
                probability = prob_phishing
            else:
                prediction = "Legitimate (An toàn)"
                probability = prob_legit

    return render_template(
        "index.html",
        selected_mode=selected_mode,
        url_input=url_input,
        prediction=prediction,
        probability=probability,
        selected_model=selected_model,
        manual_values=feature_values,
        feature_names=FEATURE_ORDER
    )


if __name__ == "__main__":
    app.run(debug=True)
