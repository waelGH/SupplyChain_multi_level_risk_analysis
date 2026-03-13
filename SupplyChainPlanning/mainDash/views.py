# Standard library imports
import base64
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import random
import time
import warnings
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from urllib.parse import urlencode
from io import TextIOWrapper

# Third-party imports
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
import pandas as pd
import requests
import seaborn as sns
import urllib3
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from geopy.geocoders import Nominatim
from openai import OpenAI

# Django imports
from django import forms
from django.conf import settings
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
from django.template import loader

# Local imports
from mainDash.static.mainDash.commodity_data import commodity_series_mapping
from .models import Case_system, Part, Component, PartSupplier, Material, MaterialSupplier, ComponentSupplier
from .network_modeling import (
    build_physical_graph,
    build_schedule_tree,
    build_selected_plan_tree,
    build_supplier_options,
    load_case_study_csvs,
    select_suppliers_for_tree,
)

# Suppress warnings
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()

# API keys loaded from environment variables
NVD_API_KEY = os.environ.get("NVD_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
SLEEP = 0.6  # respect NVD API rate limits
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


##############################################################
################# Cyber Threat related########################
##############################################################
# --- Step 1: GPT generates keywords ---
def get_keywords_from_gpt(keyword: str, max_keywords: int = 3):
    if not client:
        return []
    
    # prompt = (
    #     f"List up to {max_keywords} vendor and product keywords "
    #     f"for software, firmware, or operating systems commonly found in a {keyword}. "
    #     f"Format each as 'Vendor Product'. Do not output CPE URIs, only keywords."
    # )
    
    prompt = (
        f"List up to 3 vendor and product names that are commonly associated with a {keyword}. "
        f"Examples include software, operating systems, firmware, control systems, or embedded platforms that are realistically used in that domain. "
        f" Rules: "
        f" - Only output vendor and product names (e.g., Siemens WinCC, Microsoft Windows Embedded)."
        f" - Do not invent Common Platform Enumeration (CPE) URIs."
        f" - Do not add numbers or explanations."
        f" - Output as a plain bullet list."
    )

    response = client.chat.completions.create(
        model="gpt-4",  # or gpt-5 if available
        messages=[{"role": "user", "content": prompt}],
        max_tokens=150,
        temperature=0.4,
    )

    text = response.choices[0].message.content
    keywords = [line.lstrip("- ").strip() for line in text.splitlines() if line.strip()]
    return keywords

# --- Step 2: Search NVD CPE API ---
def search_cpes(keyword: str, max_results: int = 10):
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    r = requests.get(CPE_API, headers=HEADERS, params=params, timeout=30)
    
    # If the request failed or returned no data, just return empty
    if r.status_code != 200:
        return []
    
    #r.raise_for_status()
    products = r.json().get("products", [])
    
    return [p["cpe"]["cpeName"] for p in products if p.get("cpe")]

# --- Step 3: GPT filters real CPEs (optional) ---
def filter_cpes_with_gpt(keyword: str, cpes: list, max_results: int = 7):
    if not client:
        return cpes[:max_results]  # Return first few if no OpenAI client
    
    joined = "\n".join(f"- {c}" for c in cpes)
    prompt = (
        f"You are given real Common Platform Enumeration (CPE) 2.3 names from the NVD database. "
        f"Select up to {max_results} that are most relevant to a {keyword}. "
        f"Output them as a simple bullet list without explanation.\n\n{joined}"
    )

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=300,
        temperature=0,
    )

    text = response.choices[0].message.content
    selected = [line.lstrip("- ").strip() for line in text.splitlines() if line.strip()]
    return selected

# --- Main pipeline ---
def get_valid_cpes_for_component(component: str):
    print(f"\n🔍 Looking for CPEs for part: {component}")
    keywords = get_keywords_from_gpt(component)
    cleaned_keywords = [s.split(". ", 1)[1] if ". " in s else s for s in keywords]
    print(f"  GPT keywords: {cleaned_keywords}")

    # extract vendor names
    vendors = [s.split()[0] for s in cleaned_keywords]

    all_cpes = []
    for kw in vendors:
        cpes = search_cpes(kw, max_results=10)
        print(f"  Found {len(cpes)} CPEs for '{kw}'")
        all_cpes.extend(cpes)
        time.sleep(SLEEP)

    if not all_cpes:
        return []

    selected = filter_cpes_with_gpt(component, all_cpes, max_results=3)
    print("  Selected CPEs:",selected)
    return selected

def get_cves_for_cpe(cpe_uri, max_results=10):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": NVD_API_KEY}
    params = {
        "cpeName": cpe_uri,
        "resultsPerPage": max_results
    }

    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        print(f"Failed to get CVEs for {cpe_uri}: {response.status_code}")
        return []

    data = response.json()
    cve_items = []

    for item in data.get("vulnerabilities", []):
        cve_id = item["cve"]["id"]
        description = item["cve"]["descriptions"][0]["value"]

        metrics = item["cve"].get("metrics", {})
        score = "N/A"
        severity = "N/A"

        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]["cvssData"]
            score = metric.get("baseScore", "N/A")
            severity = metric.get("baseSeverity", "N/A")
        elif "cvssMetricV30" in metrics:
            metric = metrics["cvssMetricV30"][0]["cvssData"]
            score = metric.get("baseScore", "N/A")
            severity = metric.get("baseSeverity", "N/A")
        elif "cvssMetricV2" in metrics:
            metric = metrics["cvssMetricV2"][0]["cvssData"]
            score = metric.get("baseScore", "N/A")
            severity = metrics["cvssMetricV2"][0]['baseSeverity']
            #severity = metric.get("baseSeverity", "N/A") 
            
        else: 
            print("No CVSS metrics found for", cve_id)

        cve_items.append({
            "cpe": cpe_uri,
            "cve_id": cve_id,
            "score": score,
            "severity": severity,
            "description": description
        })

    return cve_items

########################################################################
#### Related functions to new Dashboard Views ##########################
########################################################################
def haversine_distance(lat1, lon1, lat2, lon2):
    # Radius of the Earth in miles
    R = 3958.8
    # Convert degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c

def filter_events_within_radius(events_df, supplier_lat, supplier_lon, radius_miles=50):
    def is_within_radius(event):
        event_exist = False
        distance = haversine_distance(supplier_lat, supplier_lon, event['actor1geolat'], event['actor1geolong'])
        distance2 = haversine_distance(supplier_lat, supplier_lon, event['actor2geolat'], event['actor2geolong'])
        
        if (distance <= radius_miles) | (distance2 <= radius_miles): 
            event_exist = True
        
        return event_exist

    filtered_events = events_df[events_df.apply(is_within_radius, axis=1)]
    return filtered_events

def extract_text_from_url(url):
    try:
        # Configure requests session with SSL handling
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Send GET request with timeout and SSL verification disabled for problematic sites
        response = session.get(url, timeout=10, verify=False)
        
        # Check response status
        if response.status_code == 200:
            # Parse the HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract visible text
            text = soup.get_text(separator=' ', strip=True)
            return text
        else:
            return f"Failed to retrieve content: Status {response.status_code}"
            
    except requests.exceptions.SSLError as e:
        print(f"SSL Error for URL {url}: {e}")
        return "SSL connection failed - unable to retrieve content"
    except requests.exceptions.Timeout as e:
        print(f"Timeout error for URL {url}: {e}")
        return "Request timeout - unable to retrieve content"
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error for URL {url}: {e}")
        return "Connection failed - unable to retrieve content"
    except requests.exceptions.RequestException as e:
        print(f"Request error for URL {url}: {e}")
        return f"Request failed: {str(e)}"
    except Exception as e:
        print(f"Unexpected error for URL {url}: {e}")
        return f"Unexpected error: {str(e)}"


def calculate_risk_score(filtered_event_df): 
    """
    Calculate raw risk score from GDELT event fields.
    Formula:
        raw_risk_score = average_tone + average_impact
    """ 
    if filtered_event_df is None or filtered_event_df.empty:
        print("average tone: 0.0")
        print("average impact: 0.0")
        print("raw risk score: 0.0")
        return 0.0

    tone_series = (
        pd.to_numeric(filtered_event_df["avgtone"], errors="coerce")
        if "avgtone" in filtered_event_df.columns
        else pd.Series(dtype=float)
    )
    impact_series = (
        pd.to_numeric(filtered_event_df["goldsteinscale"], errors="coerce")
        if "goldsteinscale" in filtered_event_df.columns
        else pd.Series(dtype=float)
    )

    avg_tone = float(tone_series.mean()) if not tone_series.empty else 0.0
    avg_impact = float(impact_series.mean()) if not impact_series.empty else 0.0
    raw_risk_score = avg_tone + avg_impact

    print("average tone:", avg_tone)
    print("average impact:", avg_impact)
    print("raw risk score:", raw_risk_score)

    return raw_risk_score

def analyze_supplier_risk_from_news_workflow(
    supplier_name, supplier_lat, supplier_lon, return_details=False
):
    radius_miles = 50
    max_events_rows = 100
    scan_details = {
        "risk_score": 0.0,
        "scanned_location": "Unknown",
        "radius_miles": radius_miles,
        "events_in_window": 0,
        "events_in_radius": 0,
        "articles_count": 0,
        "gdelt_events": [],
        "gdelt_events_returned": 0,
        "gdelt_events_truncated": False,
    }

    try:
        import gdelt
    except Exception as exc:
        print(f"GDELT import unavailable: {exc}")
        return scan_details if return_details else 0

    # Transform lat,long pair of the supplier into an address
    geolocator = Nominatim(user_agent="geoapi")
    location = None
    try:
        location = geolocator.reverse((supplier_lat, supplier_lon), language="en")
    except Exception as exc:
        print(f"Reverse geocoding failed for {supplier_name}: {exc}")

    print('Supplier Location.....',location)
    print('--------------------------')

    if location:
        supplier_address = location.raw.get('address', {})
        supplier_city = supplier_address.get('city', None)
        supplier_town = supplier_address.get('town', None)
        supplier_state = supplier_address.get('state', None)
        supplier_country = supplier_address.get('country', None)
        scan_details["scanned_location"] = (
            getattr(location, "address", None)
            or ", ".join(
                [value for value in [supplier_city, supplier_town, supplier_state, supplier_country] if value]
            )
            or "Unknown"
        )
        
    else:
        print("Location not found.")
        
    ############################################################################
    # Collect GDELT reports. Input: 1) time period (last week) 2) Location #####
    ############################################################################
    gd = gdelt.gdelt()   
    end_date = datetime.today()
    start_date = end_date - timedelta(days=30)  
    
    # Format dates as 'YYYY Month D'
    start_date_str = start_date.strftime('%Y %B %d')
    end_date_str = end_date.strftime('%Y %B %d')

    Last_reports = gd.Search(date=[start_date_str, end_date_str], normcols=True)
    if Last_reports is None:
        Last_reports = pd.DataFrame()

    # Save to disk
    output_path = Path(settings.BASE_DIR) / "gdelt_reports.csv"
    Last_reports.to_csv(output_path, index=False)
    
    scan_details["events_in_window"] = len(Last_reports)
    print("The number of GDELT reports in the last 30 days is", len(Last_reports)) 
    
    if (len(Last_reports) > 0): 
        ## Filter events by latitude and longitude ##
        filtered_df = filter_events_within_radius(Last_reports, supplier_lat, supplier_lon, radius_miles=radius_miles)
        scan_details["events_in_radius"] = len(filtered_df)

        if return_details:
            event_columns = [
                "globaleventid",
                "sqldate",
                "cameocodedescription",
                "avgtone",
                "goldsteinscale",
                "numarticles",
                "actor1name",
                "actor2name",
                "actiongeofullname",
                "sourceurl",
            ]
            available_event_columns = [col for col in event_columns if col in filtered_df.columns]
            events_df = filtered_df[available_event_columns].copy()
            sort_columns = [col for col in ["sqldate", "numarticles"] if col in events_df.columns]
            if sort_columns:
                events_df = events_df.sort_values(by=sort_columns, ascending=False, kind="stable")
            events_df = events_df.head(max_events_rows)
            events_df = events_df.replace({np.nan: None})

            event_rows = []
            for _, event in events_df.iterrows():
                event_rows.append(
                    {
                        "globaleventid": str(event.get("globaleventid") or ""),
                        "sqldate": str(event.get("sqldate") or ""),
                        "cameocodedescription": str(event.get("cameocodedescription") or ""),
                        "avgtone": _safe_float(event.get("avgtone"), 0.0),
                        "goldsteinscale": _safe_float(event.get("goldsteinscale"), 0.0),
                        "numarticles": _safe_int(event.get("numarticles"), 0),
                        "actor1name": str(event.get("actor1name") or ""),
                        "actor2name": str(event.get("actor2name") or ""),
                        "actiongeofullname": str(event.get("actiongeofullname") or ""),
                        "sourceurl": str(event.get("sourceurl") or ""),
                    }
                )
            scan_details["gdelt_events"] = event_rows
            scan_details["gdelt_events_returned"] = len(event_rows)
            scan_details["gdelt_events_truncated"] = len(filtered_df) > len(event_rows)

        if "numarticles" in filtered_df.columns:
            scan_details["articles_count"] = int(
                pd.to_numeric(filtered_df["numarticles"], errors="coerce").fillna(0).sum()
            )
        else:
            scan_details["articles_count"] = len(filtered_df)
        
        ## Calculate risk score from collected events
        raw_risk_score = calculate_risk_score(filtered_df)
        risk_score = float(np.clip((raw_risk_score + 5.0) / 10.0, 0.0, 1.0))
        print("RISK score (raw):", raw_risk_score)
        print("RISK score (normalized 0-1):", risk_score)
    else: 
        print('No report detected.....')
        risk_score = 0.0

    scan_details["risk_score"] = risk_score
    return scan_details if return_details else risk_score


def _risk_level_from_score(risk_score):
    score = _safe_float(risk_score, 0.0)
    score = max(0.0, min(1.0, score))
    if score >= 0.8:
        return {"label": "High Risk", "emoji": "🔴", "range": "0.8 to 1.0", "code": "high"}
    if score >= 0.6:
        return {"label": "Moderate", "emoji": "🟠", "range": "0.6 to 0.8", "code": "moderate"}
    if score >= 0.4:
        return {"label": "Mild", "emoji": "🟡", "range": "0.4 to 0.6", "code": "mild"}
    if score >= 0.2:
        return {"label": "Stable", "emoji": "🟢", "range": "0.2 to 0.4", "code": "stable"}
    return {"label": "Positive", "emoji": "🔵", "range": "0.0 to 0.2", "code": "positive"}


##############################################################
################# Structures/classes used in analysis ########
##############################################################
SUPPORTED_DATE_FORMATS = ("%Y-%m-%d", "%m/%d/%y", "%m/%d/%Y")


def _repo_root() -> Path:
    return Path(settings.BASE_DIR).resolve().parent


def _parse_optional_datetime(value):
    if pd.isna(value):
        return None
    text = str(value).strip()
    if not text:
        return None
    for date_format in SUPPORTED_DATE_FORMATS:
        try:
            return datetime.strptime(text, date_format)
        except ValueError:
            continue
    return None


def _safe_int(value, default: int = 0) -> int:
    if pd.isna(value):
        return default
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return default


def _safe_float(value, default: float = 0.0) -> float:
    if pd.isna(value):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if pd.isna(value):
        return False
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def _mc_output_dir() -> Path:
    return _repo_root() / "SC_data_generator"


def _generator_script_path() -> Path:
    return _mc_output_dir() / "case_study_data_generator.py"


@lru_cache(maxsize=1)
def _load_case_study_generator_module():
    script_path = _generator_script_path()
    if not script_path.exists():
        raise FileNotFoundError(f"Missing generator script: {script_path}")

    spec = importlib.util.spec_from_file_location("case_study_data_generator_runtime", script_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module spec from {script_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_mc_csv(filename: str):
    csv_path = _mc_output_dir() / filename
    if not csv_path.exists():
        return None
    return pd.read_csv(csv_path)


def _load_mc_report_text(filename: str = "vessel_case_study_mc_report.md"):
    report_path = _mc_output_dir() / filename
    if not report_path.exists():
        return ""
    return report_path.read_text(encoding="utf-8")


def _risk_bucket_from_probability(probability_root_impacted: float) -> str:
    score = _safe_float(probability_root_impacted, 0.0)
    if score >= 0.4:
        return "High"
    if score >= 0.15:
        return "Medium"
    return "Low"


def build_case_study_graph_model():
    nodes_df, edges_df = load_case_study_csvs(_repo_root())
    physical_graph = build_physical_graph(nodes_df, edges_df)
    schedule_tree = build_schedule_tree(physical_graph)
    supplier_options = build_supplier_options(nodes_df, edges_df)
    return nodes_df, edges_df, schedule_tree, supplier_options


def _walk_tree_nodes(schedule_tree):
    roots = [node for node, degree in schedule_tree.in_degree() if degree == 0]
    if len(roots) != 1:
        raise ValueError(f"Expected one root in schedule tree; found {roots}")
    root = roots[0]

    ordered_nodes = []

    def _dfs(node_id):
        ordered_nodes.append(node_id)
        children = sorted(
            schedule_tree.successors(node_id),
            key=lambda child: str(schedule_tree.nodes[child].get("name") or child),
        )
        for child in children:
            _dfs(child)

    _dfs(root)
    return root, ordered_nodes


def scan_risk_for_tree(schedule_tree, production_chain, risk_score=None):
    if risk_score is None:
        risk_score = {}

    _, ordered_nodes = _walk_tree_nodes(schedule_tree)
    for node_id in ordered_nodes:
        node_data = schedule_tree.nodes[node_id]
        node_name = str(node_data.get("name") or node_id)
        node_tier = str(node_data.get("node_type") or "unknown")

        risk_from_news = 0.0
        cyber_risk_score = 0

        if node_tier == "part":
            selected_entry = production_chain.get(node_name)
            if selected_entry and len(selected_entry) > 1:
                supplier_name = selected_entry[0]
                supplier_info = selected_entry[1] or {}
                supplier_lat = _safe_float(supplier_info.get("Lat"), 0.0)
                supplier_lon = _safe_float(supplier_info.get("Lon"), 0.0)

                if supplier_lat != 0.0 or supplier_lon != 0.0:
                    try:
                        risk_from_news = analyze_supplier_risk_from_news_workflow(
                            supplier_name, supplier_lat, supplier_lon
                        )
                    except Exception as exc:
                        print(f"Failed physical risk scan for {node_name}: {exc}")
                        risk_from_news = 0.0

                part_valid_cpes = get_valid_cpes_for_component(node_name)
                all_cve_data = []
                for cpe in part_valid_cpes:
                    cve_results = get_cves_for_cpe(cpe)
                    all_cve_data.extend(cve_results)
                    time.sleep(0.6)
                cyber_risk_score = len(all_cve_data)

        risk_score[node_name] = {
            "tier": node_tier,
            "risk_from_news": risk_from_news,
            "cyber_risk_score": cyber_risk_score,
        }

    return risk_score


########################################################################
#### New Dashboard Views ###############################################
########################################################################
# Index View for the dashboard (August 2025) 
def index_case_study(request):
    template = loader.get_template("mainDash/index_case_study.html")
    supplier_rows = []
    tier_order = {"tier1": 0, "tier2": 1, "tier3": 2}

    def _append_supplier_row(record, tier_key, tier_label, node_name):
        supplier_rows.append(
            {
                "tier_key": tier_key,
                "tier_label": tier_label,
                "node_name": node_name,
                "supplier_name": record.supplier_name,
                "country": record.country or "Unknown",
                "latitude": record.Lat,
                "longitude": record.Lon,
            }
        )

    component_suppliers = (
        ComponentSupplier.objects.select_related("component")
        .filter(component__isnull=False)
        .order_by("component__component_name", "supplier_name")
    )
    for record in component_suppliers:
        _append_supplier_row(
            record=record,
            tier_key="tier1",
            tier_label="Tier 1 - Component",
            node_name=record.component.component_name,
        )

    part_suppliers = (
        PartSupplier.objects.select_related("part")
        .filter(part__isnull=False)
        .order_by("part__part_name", "supplier_name")
    )
    for record in part_suppliers:
        _append_supplier_row(
            record=record,
            tier_key="tier2",
            tier_label="Tier 2 - Part",
            node_name=record.part.part_name,
        )

    material_suppliers = (
        MaterialSupplier.objects.select_related("material")
        .filter(material__isnull=False)
        .order_by("material__material_name", "supplier_name")
    )
    for record in material_suppliers:
        _append_supplier_row(
            record=record,
            tier_key="tier3",
            tier_label="Tier 3 - Raw Material",
            node_name=record.material.material_name,
        )

    supplier_rows.sort(
        key=lambda row: (
            tier_order.get(row["tier_key"], 99),
            row["node_name"],
            row["supplier_name"],
        )
    )

    map_points = [
        {
            "tier_key": row["tier_key"],
            "tier_label": row["tier_label"],
            "node_name": row["node_name"],
            "supplier_name": row["supplier_name"],
            "country": row["country"],
            "latitude": row["latitude"],
            "longitude": row["longitude"],
        }
        for row in supplier_rows
        if row["latitude"] is not None and row["longitude"] is not None
    ]

    program_name = "Next-Generation Vessel Program"
    system_name = "NextGen Vessel Platform"
    try:
        nodes_df, _ = load_case_study_csvs(_repo_root())
        program_rows = nodes_df[nodes_df["node_type"] == "program"]
        system_rows = nodes_df[nodes_df["node_type"] == "system"]
        if not program_rows.empty:
            value = str(program_rows.iloc[0].get("name") or "").strip()
            if value:
                program_name = value
        if not system_rows.empty:
            value = str(system_rows.iloc[0].get("name") or "").strip()
            if value:
                system_name = value
    except Exception:
        pass

    current_case = Case_system.objects.order_by("id").first()
    if current_case and current_case.case_name:
        system_name = current_case.case_name

    context = {
        "supplier_rows": supplier_rows,
        "supplier_map_points": map_points,
        "tier_filter_options": [
            {"value": "", "label": "All Suppliers"},
            {"value": "tier1", "label": "Tier-1 Components"},
            {"value": "tier2", "label": "Tier-2 Part Suppliers"},
            {"value": "tier3", "label": "Tier-3 Raw Material Suppliers"},
        ],
        "program_name": program_name,
        "system_name": system_name,
    }

    return HttpResponse(template.render(context, request))

def run_simulation(request):
    template = loader.get_template("mainDash/run_simulation_template.html")

    context = {}
    return HttpResponse(template.render(context, request))

def generate_plan(request):
    """
    Generate a production plan by selecting suppliers for the different system nodes.
    """
    try:
        _, _, schedule_tree, supplier_options = build_case_study_graph_model()
    except FileNotFoundError as exc:
        return JsonResponse({"status": "error", "message": f"Missing case-study CSV file: {exc}"})
    except Exception as exc:
        return JsonResponse({"status": "error", "message": f"Failed to build NetworkX model: {exc}"})

    selected_production_chain = select_suppliers_for_tree(
        schedule_tree,
        supplier_options=supplier_options,
    )
    request.session["selected_production_chain"] = json.dumps(selected_production_chain)
    request.session["plan_generated_at"] = datetime.now().isoformat()

    selected_plan_tree = build_selected_plan_tree(schedule_tree, selected_production_chain)

    return JsonResponse(
        {
            "status": "success",
            "plan": selected_production_chain,
            "plan_tree": selected_plan_tree,
        }
    )

def simulate_plan(request):
    """
    Simulate the generated production plan by analyzing risks for each supplier.
    """   

    selected_chain_json = request.session.get("selected_production_chain")
    if not selected_chain_json:
        return JsonResponse({"status": "error", "message": "No production plan found in session."})

    selected_production_chain = json.loads(selected_chain_json)

    try:
        _, _, schedule_tree, _ = build_case_study_graph_model()
    except FileNotFoundError as exc:
        return JsonResponse({"status": "error", "message": f"Missing case-study CSV file: {exc}"})
    except Exception as exc:
        return JsonResponse({"status": "error", "message": f"Failed to build NetworkX model: {exc}"})

    calculated_risk_scores = scan_risk_for_tree(schedule_tree, selected_production_chain)

    return JsonResponse({"status": "success", "risk_scores": calculated_risk_scores})


def monte_carlo_results(request):
    summary_df = _load_mc_csv("vessel_case_study_mc_summary.csv")
    ranking_df = _load_mc_csv("vessel_case_study_mc_node_ranking.csv")
    type_summary_df = _load_mc_csv("vessel_case_study_mc_type_summary.csv")
    report_text = _load_mc_report_text()

    missing_files = []
    if summary_df is None:
        missing_files.append("vessel_case_study_mc_summary.csv")
    if ranking_df is None:
        missing_files.append("vessel_case_study_mc_node_ranking.csv")

    if missing_files:
        return JsonResponse(
            {
                "status": "missing",
                "message": "Monte Carlo output files not found. Run SC_data_generator first.",
                "missing_files": missing_files,
            }
        )

    summary_row = summary_df.iloc[0].to_dict() if not summary_df.empty else {}
    top_nodes_df = ranking_df.copy()
    if "risk_bucket" not in top_nodes_df.columns and "probability_root_impacted" in top_nodes_df.columns:
        top_nodes_df["risk_bucket"] = top_nodes_df["probability_root_impacted"].apply(
            _risk_bucket_from_probability
        )
    top_nodes_df = top_nodes_df.head(10)

    type_rows = []
    if type_summary_df is not None:
        type_rows = type_summary_df.head(10).to_dict("records")

    return JsonResponse(
        {
            "status": "success",
            "summary": summary_row,
            "top_nodes": top_nodes_df.to_dict("records"),
            "type_summary": type_rows,
            "report_text": report_text,
        }
    )


def _load_or_create_selected_production_chain(request, schedule_tree):
    selected_chain_json = request.session.get("selected_production_chain")
    if selected_chain_json:
        try:
            selected_chain = json.loads(selected_chain_json)
            if isinstance(selected_chain, dict):
                return selected_chain, False
        except Exception:
            pass

    nodes_df, edges_df = load_case_study_csvs(_repo_root())
    supplier_options = build_supplier_options(nodes_df, edges_df)
    selected_chain = select_suppliers_for_tree(
        schedule_tree,
        supplier_options=supplier_options,
        seed=42,
    )
    request.session["selected_production_chain"] = json.dumps(selected_chain)
    request.session["plan_generated_at"] = datetime.now().isoformat()
    return selected_chain, True


def _supplier_assignments_by_node(schedule_tree, selected_chain):
    assignments = {}
    for node_id in schedule_tree.nodes():
        node_name = str(schedule_tree.nodes[node_id].get("name") or node_id)
        selected_entry = selected_chain.get(node_name)
        if not selected_entry:
            continue

        supplier_name = str(selected_entry[0]) if len(selected_entry) > 0 else ""
        supplier_info = selected_entry[1] if len(selected_entry) > 1 else {}
        if not isinstance(supplier_info, dict):
            supplier_info = {}

        assignments[node_id] = {
            "node_name": node_name,
            "supplier_name": supplier_name,
            "Lat": _safe_float(supplier_info.get("Lat"), 0.0),
            "Lon": _safe_float(supplier_info.get("Lon"), 0.0),
            "country": str(supplier_info.get("country") or ""),
            "delay_risk": _safe_int(supplier_info.get("delay_risk"), 0),
            "supplier_node_id": str(supplier_info.get("supplier_node_id") or ""),
        }
    return assignments


def _sample_delay_days_from_lognormal(*, risk_score: float, rng, sigma: float, max_delay_days: int) -> int:
    bounded_risk = max(0.0, min(1.0, _safe_float(risk_score, 0.0)))
    if bounded_risk <= 0.0:
        return 0

    mean_delay_days = 1.0 + bounded_risk * (max_delay_days * 0.5)
    mu = np.log(max(mean_delay_days, 1e-6)) - 0.5 * (sigma**2)
    sampled = float(rng.lognormal(mean=mu, sigma=sigma))
    sampled_days = max(1, int(round(sampled)))
    return min(sampled_days, max_delay_days)


def _simulate_network_disruption_multi(*, tree, schedule, injected_delay_by_node):
    simulated_finish = {}
    simulated_start = {}
    incoming_delay_by_node = {}
    absorbed_by_buffer_by_node = {}

    bottom_up_nodes = sorted(
        tree.nodes(),
        key=lambda node_id: (schedule[node_id]["layer_id"], str(node_id)),
        reverse=True,
    )

    for node_id in bottom_up_nodes:
        rec = schedule[node_id]
        baseline_start = rec["integration_start"]
        baseline_finish = rec["need_by_date"]
        node_buffer_days = int(rec.get("sampled_buffer_days") or 0)

        child_induced_delay = 0
        if baseline_start is not None:
            for child_id in tree.successors(node_id):
                child_finish = simulated_finish[child_id]
                child_lateness = (child_finish - baseline_start).days
                child_induced_delay = max(child_induced_delay, max(0, child_lateness))

        injected_delay = max(0, _safe_int(injected_delay_by_node.get(node_id), 0))
        incoming_delay_days = max(injected_delay, child_induced_delay)
        absorbed_by_buffer_days = min(node_buffer_days, incoming_delay_days)
        finish_delay_days = max(0, incoming_delay_days - node_buffer_days)

        sim_finish = baseline_finish + timedelta(days=finish_delay_days)
        sim_start = (
            baseline_start + timedelta(days=finish_delay_days)
            if baseline_start is not None
            else None
        )

        simulated_finish[node_id] = sim_finish
        simulated_start[node_id] = sim_start
        incoming_delay_by_node[node_id] = incoming_delay_days
        absorbed_by_buffer_by_node[node_id] = absorbed_by_buffer_days

    rows = []
    ordered_nodes = sorted(
        tree.nodes(),
        key=lambda node_id: (schedule[node_id]["layer_id"], str(node_id)),
    )
    for node_id in ordered_nodes:
        rec = schedule[node_id]
        baseline_start = rec["integration_start"]
        baseline_finish = rec["need_by_date"]
        sim_start = simulated_start[node_id]
        sim_finish = simulated_finish[node_id]
        finish_delay_days = int((sim_finish - baseline_finish).days)
        start_delay_days = (
            int((sim_start - baseline_start).days)
            if baseline_start is not None and sim_start is not None
            else 0
        )
        injected_delay_days = max(0, _safe_int(injected_delay_by_node.get(node_id), 0))

        rows.append(
            {
                "node_id": node_id,
                "node_type": rec["node_type"],
                "layer_id": rec["layer_id"],
                "original_start_date": baseline_start.isoformat() if baseline_start is not None else "",
                "original_finish_date": baseline_finish.isoformat(),
                "simulated_start_date": sim_start.isoformat() if sim_start is not None else "",
                "simulated_finish_date": sim_finish.isoformat(),
                "start_delay_days": start_delay_days,
                "finish_delay_days": finish_delay_days,
                "incoming_delay_days": incoming_delay_by_node[node_id],
                "absorbed_by_buffer_days": absorbed_by_buffer_by_node[node_id],
                "sampled_buffer_days": int(rec.get("sampled_buffer_days") or 0),
                "impacted": bool(finish_delay_days > 0),
                "is_disrupted_node": bool(injected_delay_days > 0),
                "injected_delay_days": injected_delay_days,
            }
        )

    return pd.DataFrame(rows)


def deterministic_results(request):
    try:
        gen = _load_case_study_generator_module()
        base_dir = _mc_output_dir()
        nodes_path = base_dir / "__vessel_nodes_realistic_case_study_with_dates.csv"
        edges_path = base_dir / "__vessel_edges_case_study.csv"
        config_path = base_dir / "config.json"
        nodes_df, edges_df, config = gen.load_generator_inputs(nodes_path, edges_path, config_path)
        _, schedule_tree, schedule = gen.generate_baseline_data(nodes_df, edges_df, config, seed=42)
    except FileNotFoundError as exc:
        return JsonResponse(
            {
                "status": "missing",
                "message": f"Missing deterministic simulation input file: {exc}",
                "missing_files": [str(exc)],
            }
        )
    except Exception as exc:
        return JsonResponse(
            {
                "status": "error",
                "message": f"Failed to initialize deterministic simulation model: {exc}",
                "missing_files": [],
            }
        )

    roots = [node for node, degree in schedule_tree.in_degree() if degree == 0]
    if len(roots) != 1:
        return JsonResponse(
            {"status": "error", "message": "Invalid schedule tree root structure.", "missing_files": []}
        )
    root = roots[0]
    candidate_nodes = sorted(node for node in schedule_tree.nodes() if node != root)
    if not candidate_nodes:
        return JsonResponse(
            {"status": "error", "message": "No non-root nodes available for disruption.", "missing_files": []}
        )

    simulation_cfg = config.get("simulation", {})
    delay_range = simulation_cfg.get("delay_days_range", [7, 45])
    try:
        delay_lo = int(delay_range[0])
        delay_hi = int(delay_range[1])
    except Exception:
        delay_lo, delay_hi = 7, 45
    if delay_lo > delay_hi:
        delay_lo, delay_hi = delay_hi, delay_lo

    scenario_rng = random.SystemRandom()
    disrupted_node_id = scenario_rng.choice(candidate_nodes)
    injected_delay_days = scenario_rng.randint(delay_lo, delay_hi)

    try:
        network_df = gen.simulate_network_disruption(
            tree=schedule_tree,
            schedule=schedule,
            disrupted_node_id=disrupted_node_id,
            delay_days=injected_delay_days,
        )
    except Exception as exc:
        return JsonResponse(
            {"status": "error", "message": f"Failed to run deterministic simulation: {exc}", "missing_files": []}
        )

    root_row = network_df[network_df["layer_id"] == 0].iloc[0]
    impacted_count = int(network_df["impacted"].apply(_safe_bool).sum())
    root_delay_days = _safe_int(root_row.get("finish_delay_days"), 0)
    root_impacted = bool(root_delay_days > 0)

    ranked_nodes = network_df.copy()
    ranked_nodes["finish_delay_days"] = pd.to_numeric(ranked_nodes["finish_delay_days"], errors="coerce").fillna(0)
    ranked_nodes["absorbed_by_buffer_days"] = pd.to_numeric(
        ranked_nodes["absorbed_by_buffer_days"], errors="coerce"
    ).fillna(0)
    ranked_nodes["impacted"] = ranked_nodes["impacted"].apply(_safe_bool)
    ranked_nodes["is_disrupted_node"] = ranked_nodes["is_disrupted_node"].apply(_safe_bool)
    ranked_nodes = ranked_nodes.sort_values(
        by=["finish_delay_days", "absorbed_by_buffer_days", "node_id"],
        ascending=[False, False, True],
    ).head(10)

    absorber_node_id = ""
    absorber_rows = network_df[
        (pd.to_numeric(network_df.get("incoming_delay_days", 0), errors="coerce").fillna(0) > 0)
        & (pd.to_numeric(network_df.get("absorbed_by_buffer_days", 0), errors="coerce").fillna(0) > 0)
        & (pd.to_numeric(network_df.get("finish_delay_days", 0), errors="coerce").fillna(0) == 0)
        & (~network_df["is_disrupted_node"].apply(_safe_bool))
    ]
    if not absorber_rows.empty:
        absorber_node_id = str(absorber_rows.iloc[0].get("node_id") or "")

    explanation = {
        "absorber_node_id": absorber_node_id,
        "stopped_before_root": bool(not root_impacted),
        "reached_root": bool(root_impacted),
    }

    summary = {
        "disrupted_node_id": disrupted_node_id,
        "injected_delay_days": injected_delay_days,
        "root_impacted": root_impacted,
        "root_delay_days": root_delay_days,
        "total_impacted_nodes": impacted_count,
    }

    return JsonResponse(
        {
            "status": "success",
            "summary": summary,
            "top_nodes": ranked_nodes[
                ["node_id", "finish_delay_days", "absorbed_by_buffer_days", "impacted", "is_disrupted_node"]
            ].to_dict("records"),
            "explanation": explanation,
            "report_text": "",
        }
    )


def scan_based_simulation_results(request):
    try:
        gen = _load_case_study_generator_module()
        base_dir = _mc_output_dir()
        nodes_path = base_dir / "__vessel_nodes_realistic_case_study_with_dates.csv"
        edges_path = base_dir / "__vessel_edges_case_study.csv"
        config_path = base_dir / "config.json"
        nodes_df, edges_df, config = gen.load_generator_inputs(nodes_path, edges_path, config_path)
        _, schedule_tree, schedule = gen.generate_baseline_data(nodes_df, edges_df, config, seed=42)
    except FileNotFoundError as exc:
        return JsonResponse(
            {
                "status": "missing",
                "message": f"Missing scan-based simulation input file: {exc}",
                "missing_files": [str(exc)],
            }
        )
    except Exception as exc:
        return JsonResponse(
            {
                "status": "error",
                "message": f"Failed to initialize scan-based simulation model: {exc}",
                "missing_files": [],
            }
        )

    try:
        selected_chain, auto_plan_generated = _load_or_create_selected_production_chain(request, schedule_tree)
        assignments = _supplier_assignments_by_node(schedule_tree, selected_chain)
    except Exception as exc:
        return JsonResponse(
            {"status": "error", "message": f"Unable to load assigned suppliers: {exc}", "missing_files": []}
        )

    cfg = config.get("scan_based_simulation", {})
    risk_detection_threshold = max(0.0, min(1.0, _safe_float(cfg.get("risk_detection_threshold"), 0.6)))
    lognormal_sigma = max(0.05, _safe_float(cfg.get("lognormal_sigma"), 0.55))
    max_delay_days = max(1, _safe_int(cfg.get("max_delay_days"), 45))
    rng_seed = _safe_int(cfg.get("seed"), 42)
    rng = np.random.default_rng(rng_seed)

    supplier_scan_rows = []
    injected_delay_by_node = {}
    risk_cache = {}
    ordered_node_ids = sorted(
        schedule_tree.nodes(),
        key=lambda node_id: (schedule[node_id]["layer_id"], str(node_id)),
    )
    for node_id in ordered_node_ids:
        rec = schedule[node_id]
        node_name = str(schedule_tree.nodes[node_id].get("name") or node_id)
        node_type = str(rec.get("node_type") or schedule_tree.nodes[node_id].get("node_type") or "unknown")
        assignment = assignments.get(node_id)
        if not assignment:
            supplier_scan_rows.append(
                {
                    "node_id": node_id,
                    "node_name": node_name,
                    "node_type": node_type,
                    "layer_id": _safe_int(rec.get("layer_id"), 0),
                    "supplier_name": "",
                    "risk_score": 0.0,
                    "risk_detected": False,
                    "scanned": False,
                    "injected_delay_days": 0,
                    "scan_error": "",
                }
            )
            continue

        supplier_name = str(assignment.get("supplier_name") or "")
        supplier_lat = _safe_float(assignment.get("Lat"), 0.0)
        supplier_lon = _safe_float(assignment.get("Lon"), 0.0)
        can_scan = bool(supplier_lat != 0.0 or supplier_lon != 0.0)
        scan_error = ""
        risk_score = 0.0

        if can_scan:
            cache_key = (supplier_name, round(supplier_lat, 6), round(supplier_lon, 6))
            if cache_key in risk_cache:
                risk_score = risk_cache[cache_key]
            else:
                try:
                    risk_score = _safe_float(
                        analyze_supplier_risk_from_news_workflow(supplier_name, supplier_lat, supplier_lon),
                        0.0,
                    )
                except Exception as exc:
                    scan_error = str(exc)
                    risk_score = 0.0
                risk_cache[cache_key] = risk_score

        risk_detected = bool(can_scan and risk_score >= risk_detection_threshold)
        injected_delay_days = (
            _sample_delay_days_from_lognormal(
                risk_score=risk_score,
                rng=rng,
                sigma=lognormal_sigma,
                max_delay_days=max_delay_days,
            )
            if risk_detected
            else 0
        )
        if injected_delay_days > 0:
            injected_delay_by_node[node_id] = injected_delay_days

        supplier_scan_rows.append(
            {
                "node_id": node_id,
                "node_name": node_name,
                "node_type": node_type,
                "layer_id": _safe_int(rec.get("layer_id"), 0),
                "supplier_name": supplier_name,
                "risk_score": max(0.0, min(1.0, risk_score)),
                "risk_detected": risk_detected,
                "scanned": can_scan,
                "injected_delay_days": injected_delay_days,
                "scan_error": scan_error,
            }
        )

    try:
        network_df = _simulate_network_disruption_multi(
            tree=schedule_tree,
            schedule=schedule,
            injected_delay_by_node=injected_delay_by_node,
        )
    except Exception as exc:
        return JsonResponse(
            {"status": "error", "message": f"Failed to run scan-based simulation: {exc}", "missing_files": []}
        )

    roots = [node for node, degree in schedule_tree.in_degree() if degree == 0]
    if len(roots) != 1:
        return JsonResponse(
            {"status": "error", "message": "Invalid schedule tree root structure.", "missing_files": []}
        )
    root = roots[0]
    root_row = network_df[network_df["node_id"] == root].iloc[0]
    root_delay_days = _safe_int(root_row.get("finish_delay_days"), 0)
    root_impacted = bool(root_delay_days > 0)
    impacted_count = int(network_df["impacted"].apply(_safe_bool).sum())

    ranked_nodes = network_df.copy()
    ranked_nodes["finish_delay_days"] = pd.to_numeric(ranked_nodes["finish_delay_days"], errors="coerce").fillna(0)
    ranked_nodes["absorbed_by_buffer_days"] = pd.to_numeric(
        ranked_nodes["absorbed_by_buffer_days"], errors="coerce"
    ).fillna(0)
    ranked_nodes["injected_delay_days"] = pd.to_numeric(
        ranked_nodes["injected_delay_days"], errors="coerce"
    ).fillna(0)
    ranked_nodes["impacted"] = ranked_nodes["impacted"].apply(_safe_bool)
    ranked_nodes["is_disrupted_node"] = ranked_nodes["is_disrupted_node"].apply(_safe_bool)

    scan_by_node = {row["node_id"]: row for row in supplier_scan_rows}
    ranked_nodes["supplier_name"] = ranked_nodes["node_id"].map(
        lambda node_id: str((assignments.get(node_id) or {}).get("supplier_name") or "")
    )
    ranked_nodes["risk_score"] = ranked_nodes["node_id"].map(
        lambda node_id: _safe_float((scan_by_node.get(node_id) or {}).get("risk_score"), 0.0)
    )

    ranked_nodes = ranked_nodes.sort_values(
        by=["finish_delay_days", "injected_delay_days", "absorbed_by_buffer_days", "node_id"],
        ascending=[False, False, False, True],
    ).head(15)

    absorber_node_id = ""
    absorber_rows = network_df[
        (pd.to_numeric(network_df.get("incoming_delay_days", 0), errors="coerce").fillna(0) > 0)
        & (pd.to_numeric(network_df.get("absorbed_by_buffer_days", 0), errors="coerce").fillna(0) > 0)
        & (pd.to_numeric(network_df.get("finish_delay_days", 0), errors="coerce").fillna(0) == 0)
        & (pd.to_numeric(network_df.get("injected_delay_days", 0), errors="coerce").fillna(0) == 0)
    ]
    if not absorber_rows.empty:
        absorber_node_id = str(absorber_rows.iloc[0].get("node_id") or "")

    scanned_suppliers = int(sum(1 for row in supplier_scan_rows if row["scanned"]))
    risky_suppliers = int(sum(1 for row in supplier_scan_rows if row["risk_detected"]))
    nodes_with_injected_delay = int(sum(1 for delay in injected_delay_by_node.values() if delay > 0))
    total_injected_delay_days = int(sum(injected_delay_by_node.values()))

    summary = {
        "root_impacted": root_impacted,
        "root_delay_days": root_delay_days,
        "total_impacted_nodes": impacted_count,
        "scanned_suppliers": scanned_suppliers,
        "risky_suppliers_detected": risky_suppliers,
        "nodes_with_injected_delay": nodes_with_injected_delay,
        "total_injected_delay_days": total_injected_delay_days,
        "risk_detection_threshold": risk_detection_threshold,
        "lognormal_sigma": lognormal_sigma,
        "max_delay_days": max_delay_days,
        "auto_plan_generated": bool(auto_plan_generated),
    }

    explanation = {
        "absorber_node_id": absorber_node_id,
        "stopped_before_root": bool(not root_impacted),
        "reached_root": bool(root_impacted),
        "seed": rng_seed,
    }

    supplier_scan_rows.sort(
        key=lambda row: (-_safe_int(row.get("injected_delay_days"), 0), -_safe_float(row.get("risk_score"), 0.0), row["node_id"])
    )

    return JsonResponse(
        {
            "status": "success",
            "summary": summary,
            "top_nodes": ranked_nodes[
                [
                    "node_id",
                    "supplier_name",
                    "risk_score",
                    "injected_delay_days",
                    "finish_delay_days",
                    "absorbed_by_buffer_days",
                    "impacted",
                    "is_disrupted_node",
                ]
            ].to_dict("records"),
            "supplier_scans": supplier_scan_rows,
            "explanation": explanation,
            "report_text": "",
        }
    )


def get_suppliers_for_part(request, part_id):
    try:
        part = Part.objects.get(id=part_id)
        suppliers = PartSupplier.objects.filter(part=part)
        print('show supliers for part', part_id, suppliers)

        materials = Material.objects.filter(part=part)
        raw_suppliers = MaterialSupplier.objects.filter(material__in=materials)

        supplier_data = [
            {
                "name": s.supplier_name,
                "latitude": s.Lat,
                "longitude": s.Lon,
                "quality": s.quality,
                "delay_risk": s.delay_risk,
                "naic_code": s.NAIC_code,
                "hs_code": s.HS_code,
            }
            for s in suppliers
        ]

        raw_supplier_data = [
            {
                "name": s.supplier_name,
                "latitude": s.Lat,
                "longitude": s.Lon,
                "material_name": s.material.material_name,
            }
            for s in raw_suppliers
        ]


        return JsonResponse({"success": True, "suppliers": supplier_data, "raw_suppliers": raw_supplier_data})
    except Part.DoesNotExist:
        return JsonResponse({"success": False, "error": "Part not found."})
    
def scan_analysis(request):
    pair_key = request.GET.get("pair_key", "").strip()
    if pair_key:
        selected_pair = _resolve_physical_pair(pair_key)
        if not selected_pair:
            return JsonResponse(
                {"status": "error", "message": "Invalid node and supplier selection."},
                status=400,
            )

        part_to_search = selected_pair["node_name"]
        selected_supplier_name = selected_pair["supplier_name"]

        try:
            all_cve_data = []
            part_valid_cpes = get_valid_cpes_for_component(part_to_search)
            print("\n✅ Valid CPEs (from NVD):")
            for cpe in part_valid_cpes:
                print(f"- {cpe}")

            for cpe in part_valid_cpes:
                print(f"Querying CVEs for {cpe}...")
                cve_results = get_cves_for_cpe(cpe)
                if not cve_results:
                    print("⚠️ No results, skipping...")
                all_cve_data.extend(cve_results)
                time.sleep(0.6)

            if len(all_cve_data) > 0:
                result = {
                    "status": "ok",
                    "message": (
                        f"Found {len(all_cve_data)} CVEs for "
                        f"{selected_pair['node_type'].lower()} '{part_to_search}'"
                    ),
                    "node_type": selected_pair["node_type"],
                    "node_name": part_to_search,
                    "supplier_name": selected_supplier_name,
                    "cve_data": all_cve_data,
                    "CVE IDs": [entry["cve_id"] for entry in all_cve_data],
                    "Severities": [entry["severity"] for entry in all_cve_data],
                    "Scores": [entry["score"] for entry in all_cve_data],
                    "Descriptions": [entry["description"] for entry in all_cve_data],
                }
            else:
                result = {
                    "status": "ok",
                    "message": (
                        f"No CVEs found for {selected_pair['node_type'].lower()} "
                        f"'{part_to_search}'"
                    ),
                    "node_type": selected_pair["node_type"],
                    "node_name": part_to_search,
                    "supplier_name": selected_supplier_name,
                    "cve_data": [],
                    "CVE IDs": [],
                    "Severities": [],
                    "Scores": [],
                    "Descriptions": [],
                }

            return JsonResponse(result)
        except Exception as exc:
            return JsonResponse(
                {"status": "error", "message": f"Cyber scan failed: {exc}"},
                status=500,
            )

    component_id = request.GET.get("component_id")
    supplier_id = request.GET.get("supplier_id")

    if not component_id or not supplier_id:
        return JsonResponse({"status": "error", "message": "Missing component or supplier ID"})

    try:
        parts = Part.objects.get(id=component_id)
        part_supplier = PartSupplier.objects.filter(supplier_name=supplier_id).first()
        
        ########################################################################################
        ############### Perform analysis: call NVD API ##############################
        ########################################################################################
        part_to_search = parts.part_name
        
        # from part: get possible CPEs
        part_valid_cpes = get_valid_cpes_for_component(part_to_search)
        print("\n✅ Valid CPEs (from NVD):")
        for cpe in part_valid_cpes:
            print(f"- {cpe}")

        # # Main collection loop
        all_cve_data = []
        for cpe in part_valid_cpes:
            print(f"Querying CVEs for {cpe}...")
            cve_results = get_cves_for_cpe(cpe)
            
            if not cve_results:  # Empty list check
                print("⚠️ No results, skipping...")
            
            all_cve_data.extend(cve_results)
            time.sleep(0.6)  # To stay under rate limits

        # Print results
        for entry in all_cve_data:
            print(f"\nCPE: {entry['cpe']}")
            print(f"  CVE ID:     {entry['cve_id']}")
            print(f"  Severity:   {entry['severity']}")
            print(f"  Score:      {entry['score']}")
            print(f"  Description:{entry['description'][:100]}...")

        ########################################################################################
        ########################################################################################
        if len(all_cve_data) > 0:
            result = {
                "status": "ok",         
                "message": f"Found {len(all_cve_data)} CVEs for part '{part_to_search}'",
                "cve_data": all_cve_data,
                "CVE IDs": [entry['cve_id'] for entry in all_cve_data],
                "Severities": [entry['severity'] for entry in all_cve_data],
                "Scores": [entry['score'] for entry in all_cve_data],
                "Descriptions": [entry['description'] for entry in all_cve_data],
            }
        else:
            result = {
                "status": "ok",         
                "message": f"No CVEs found for part '{part_to_search}'",
                "cve_data": [],
                "CVE IDs": [],
                "Severities": [],
                "Scores": [],
                "Descriptions": [],
            }
        
        return JsonResponse(result)
    except Component.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Component not found"})
    except PartSupplier.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Supplier not found"})

def get_dropdown_data(request):
    parts = Part.objects.all()
    part_options = [{"id": part.id, "name": part.part_name} for part in parts]

    suppliers = PartSupplier.objects.all()
    supplier_options = [{"id": supplier.id, "name": supplier.supplier_name,"part_name": supplier.part.part_name} for supplier in suppliers]

    return JsonResponse({
        "suppliers": supplier_options
    })


def _build_physical_node_supplier_groups():
    component_pairs = []
    part_pairs = []
    material_pairs = []

    component_suppliers = (
        ComponentSupplier.objects.select_related("component")
        .filter(component__isnull=False)
        .order_by("component__component_name", "supplier_name")
    )
    for supplier in component_suppliers:
        component_pairs.append(
            {
                "pair_key": f"component:{supplier.id}",
                "node_type": "Component",
                "node_name": supplier.component.component_name,
                "supplier_name": supplier.supplier_name,
            }
        )

    part_suppliers = (
        PartSupplier.objects.select_related("part")
        .filter(part__isnull=False)
        .order_by("part__part_name", "supplier_name")
    )
    for supplier in part_suppliers:
        part_pairs.append(
            {
                "pair_key": f"part:{supplier.id}",
                "node_type": "Part",
                "node_name": supplier.part.part_name,
                "supplier_name": supplier.supplier_name,
            }
        )

    material_suppliers = (
        MaterialSupplier.objects.select_related("material")
        .filter(material__isnull=False)
        .order_by("material__material_name", "supplier_name")
    )
    for supplier in material_suppliers:
        material_pairs.append(
            {
                "pair_key": f"material:{supplier.id}",
                "node_type": "Material",
                "node_name": supplier.material.material_name,
                "supplier_name": supplier.supplier_name,
            }
        )

    return {
        "component_pairs": component_pairs,
        "part_pairs": part_pairs,
        "material_pairs": material_pairs,
    }


def _resolve_physical_pair(pair_key):
    if ":" not in pair_key:
        return None

    pair_type, record_id = pair_key.split(":", 1)
    if not record_id.isdigit():
        return None

    selected_id = int(record_id)

    if pair_type == "component":
        record = (
            ComponentSupplier.objects.select_related("component")
            .filter(id=selected_id, component__isnull=False)
            .first()
        )
        if not record:
            return None
        return {
            "node_type": "Component",
            "node_name": record.component.component_name,
            "supplier_name": record.supplier_name,
            "supplier_lat": record.Lat,
            "supplier_lon": record.Lon,
        }

    if pair_type == "part":
        record = (
            PartSupplier.objects.select_related("part")
            .filter(id=selected_id, part__isnull=False)
            .first()
        )
        if not record:
            return None
        return {
            "node_type": "Part",
            "node_name": record.part.part_name,
            "supplier_name": record.supplier_name,
            "supplier_lat": record.Lat,
            "supplier_lon": record.Lon,
        }

    if pair_type == "material":
        record = (
            MaterialSupplier.objects.select_related("material")
            .filter(id=selected_id, material__isnull=False)
            .first()
        )
        if not record:
            return None
        return {
            "node_type": "Material",
            "node_name": record.material.material_name,
            "supplier_name": record.supplier_name,
            "supplier_lat": record.Lat,
            "supplier_lon": record.Lon,
        }

    return None


def scan_cyber_layer(request):
    grouped_pairs = _build_physical_node_supplier_groups()
    cyber_pairs = grouped_pairs["part_pairs"] + grouped_pairs["material_pairs"]
    context = {
        "part_pairs": grouped_pairs["part_pairs"],
        "material_pairs": grouped_pairs["material_pairs"],
        "total_pairs": len(cyber_pairs),
    }

    return render(request, "mainDash/scan_cyber_layer.html", context)

def scan_supply_chain(request):
    grouped_pairs = _build_physical_node_supplier_groups()
    total_pairs = (
        len(grouped_pairs["component_pairs"])
        + len(grouped_pairs["part_pairs"])
        + len(grouped_pairs["material_pairs"])
    )
    context = {
        **grouped_pairs,
        "total_pairs": total_pairs,
    }
    return render(request, "mainDash/supply_chain_analysis.html", context)

def perform_analysis_view(request):
    pair_key = request.GET.get("pair_key", "").strip()
    if not pair_key:
        return JsonResponse(
            {"status": "error", "message": "Missing node and supplier selection."},
            status=400,
        )

    selected_pair = _resolve_physical_pair(pair_key)
    if not selected_pair:
        return JsonResponse(
            {"status": "error", "message": "Invalid node and supplier selection."},
            status=400,
        )

    try:
        scan_details = analyze_supplier_risk_from_news_workflow(
            selected_pair["supplier_name"],
            selected_pair["supplier_lat"],
            selected_pair["supplier_lon"],
            return_details=True,
        )
        risk_score = _safe_float(scan_details.get("risk_score"), 0.0)
        risk_level = _risk_level_from_score(risk_score)
    except Exception as exc:
        return JsonResponse(
            {
                "status": "error",
                "message": (
                    f"Unable to perform analysis for selected pair "
                    f"{selected_pair['node_name']} / {selected_pair['supplier_name']}: {exc}"
                ),
            },
            status=500,
        )

    return JsonResponse(
        {
            "status": "success",
            "node_type": selected_pair["node_type"],
            "node_name": selected_pair["node_name"],
            "supplier_name": selected_pair["supplier_name"],
            "risk_score": risk_score,
            "risk_level": risk_level,
            "scan_details": {
                "scanned_location": str(scan_details.get("scanned_location") or "Unknown"),
                "articles_count": _safe_int(scan_details.get("articles_count"), 0),
                "events_in_window": _safe_int(scan_details.get("events_in_window"), 0),
                "events_in_radius": _safe_int(scan_details.get("events_in_radius"), 0),
                "radius_miles": _safe_float(scan_details.get("radius_miles"), 50.0),
                "gdelt_events": scan_details.get("gdelt_events") or [],
                "gdelt_events_returned": _safe_int(scan_details.get("gdelt_events_returned"), 0),
                "gdelt_events_truncated": bool(scan_details.get("gdelt_events_truncated")),
            },
        }
    )

def upload_case_parts_data(request):
    if request.method == 'POST':
        form = CSVUploadFormBOM(request.POST, request.FILES)
        if form.is_valid():

            csv_file = request.FILES['csv_file']

            # delete old data first
            #Item.objects.all().delete()

            data = []
            i = 0
            for line in csv_file:
                row = line.decode('utf-8').strip().split(',')

                # Parse date from MM/DD/YY to YYYY-MM-DD
                try:
                    date_req_modified = datetime.strptime(row[7], "%m/%d/%y")
                except ValueError:
                    date_req_modified = None  # or handle error as needed

                if i != 0 :
                    system_name = row[0].strip()
                    component_name = row[2].strip()

                    # Create/get System
                    system_obj, _ = Case_system.objects.get_or_create(case_name=system_name)

                    # Create/get Component
                    component_obj, _ = Component.objects.get_or_create(
                        component_name=component_name,
                        case_system=system_obj
                    )
                    
                    # Create new Part instance
                    new_part = Part(
                        part_number = row[1],
                        component = component_obj,
                        part_name = row[3],
                        quantity = row[4],
                        criticality = row[5],
                        NAIC_code = row[6],
                        date_req = date_req_modified,
                        HS_code = row[8]
                    )

                    # Save the new instance to the database
                    new_part.save()
                data.append(row)
                i += 1

            return render(request, 'mainDash/uploaded_data.html', {'data': data})
        
    else:
        form = CSVUploadFormBOM()
    
    return render(request, 'mainDash/upload_csv.html', {'form': form, 'form_title': 'Upload Data'})

def upload_case_supplier_data(request):
    if request.method == 'POST':
        form = CSVUploadFormBOM(request.POST, request.FILES)
        if form.is_valid():
            csv_file = request.FILES['csv_file']

            # delete old data first
            #Item.objects.all().delete()

            data = []
            i = 0
            for line in csv_file:
                row = line.decode('utf-8').strip().split(',')

                if i != 0 :
                    part_id = row[0].strip()
                    component_name= row[1].strip()
                    supplier_name = row[2].strip()
                    Lat = row[3]
                    Long = row[4]
                    supplier_quality = int(row[5])
                    delay_risk = int(row[6])
                    naic_code = row[7].strip()
                    hs_code = row[8].strip()
                    try: 
                        part_instance = Part.objects.get(id=part_id)
                    except Part.DoesNotExist:
                        part_instance = None

                    new_part_supplier = PartSupplier(
                        part = part_instance,
                        supplier_name = supplier_name,
                        Lat = Lat,
                        Lon = Long,
                        quality = supplier_quality,
                        delay_risk = delay_risk,
                        HS_code = hs_code,
                        NAIC_code = naic_code,
                        date_created = datetime.now()
                    )

                    # Save the new instance to the database
                    new_part_supplier.save()
                data.append(row)
                i += 1

            return render(request, 'mainDash/uploaded_data.html', {'data': data})
        
    else:
        form = CSVUploadFormBOM()
    
    return render(request, 'mainDash/upload_csv.html', {'form': form, 'form_title': 'Upload Suppliers Data'})

def upload_material_data(request):
    if request.method == 'POST':
        form = CSVUploadFormBOM(request.POST, request.FILES)

        if form.is_valid():
            csv_file = request.FILES['csv_file']

            # delete old data first
            #Item.objects.all().delete()

            data = []
            i = 0
            for line in csv_file:
                row = line.decode('utf-8').strip().split(',')

                if i != 0 :
                    part_name = row[1].strip()
                    material_name= row[2].strip()
                    raw_supplier_name = row[3].strip()
                    raw_qty = int(row[4])
                    raw_criticality = int(row[5])
                    # Parse date from MM/DD/YY to YYYY-MM-DD
                    try:
                        raw_date_req = datetime.strptime(row[6], "%m/%d/%y")
                    except ValueError:
                        raw_date_req = None  # or handle error as needed
                    raw_risk= int(row[7])
                    Lat = row[8]
                    Long = row[9]

                    try: 
                        part_instance = Part.objects.filter(part_name=part_name).first()
                    except Part.DoesNotExist:
                        part_instance = None
                    if part_instance:
                        new_material = Material(
                            part = part_instance,
                            material_name = material_name,
                            material_description = "",
                            quantity = raw_qty,
                            date_req = raw_date_req,
                            criticality = raw_criticality,
                            date_created = datetime.now()
                        )
                        # Save the new instance to the database
                        new_material.save()

                        new_supplier = MaterialSupplier(
                            material = new_material,
                            supplier_name = raw_supplier_name,
                            Lat = Lat,
                            Lon = Long,
                            quality = 0,  # Assuming quality is not provided in the CSV
                            delay_risk = raw_risk,
                            NAIC_code = "",  # Assuming NAIC code is not provided in the CSV
                            HS_code = "",  # Assuming HS code is not provided in the CSV
                            date_created = datetime.now()
                        )
                        # Save the new instance to the database
                        new_supplier.save()
                    else:
                        print(f"Part with name {part_name} not found. Skipping material creation.")

                data.append(row)
                i += 1

            return render(request, 'mainDash/uploaded_data.html', {'data': data})
        
    else:
        form = CSVUploadFormBOM()

    return render(request, 'mainDash/upload_csv.html', {'form': form, 'form_title': 'Upload Material Data'})


###################################################################################################################
##### Rebuilds your entire vessel case-study dataset inside  Django database from CSV-derived DataFrames ##########
###################################################################################################################
@transaction.atomic
def _load_case_study_into_database():
    nodes_df, edges_df, _, supplier_options = build_case_study_graph_model()

    # Rebuild case-study data deterministically from CSV source files.
    MaterialSupplier.objects.all().delete()
    PartSupplier.objects.all().delete()
    ComponentSupplier.objects.all().delete()
    Material.objects.all().delete()
    Part.objects.all().delete()
    Component.objects.all().delete()
    Case_system.objects.all().delete()

    system_rows = nodes_df[nodes_df["node_type"] == "system"]
    if system_rows.empty:
        raise ValueError("No system node found in nodes CSV.")

    system_row = system_rows.iloc[0]
    system_node_id = str(system_row["node_id"])
    system_name = str(system_row.get("name") or "Vessel System")
    system_case = Case_system.objects.create(
        case_name=system_name,
        case_description="Loaded from SC_data_generator vessel case-study CSV files.",
        system_node_id=system_node_id,
    )

    assembly_edges = edges_df[edges_df["edge_type"] == "assembly_dependency"][
        ["src", "dst", "qty_per_parent"]
    ]
    material_edges = edges_df[edges_df["edge_type"] == "material_input"][
        ["src", "dst", "qty_per_parent"]
    ]

    part_parent_lookup = {}
    for _, row in assembly_edges.iterrows():
        part_parent_lookup[str(row["src"])] = {
            "component_node_id": str(row["dst"]),
            "quantity": max(1, _safe_int(row.get("qty_per_parent"), 1)),
        }

    material_parent_lookup = {}
    for _, row in material_edges.iterrows():
        material_parent_lookup[str(row["src"])] = {
            "part_node_id": str(row["dst"]),
            "quantity": max(1, _safe_int(row.get("qty_per_parent"), 1)),
        }

    components_by_node_id = {}
    component_rows = nodes_df[nodes_df["node_type"] == "component"].sort_values("name")
    for _, row in component_rows.iterrows():
        node_id = str(row["node_id"])
        component = Component.objects.create(
            node_id=node_id,
            component_name=str(row.get("name") or node_id),
            component_description=f"Loaded from node {node_id}",
            case_system=system_case,
        )
        components_by_node_id[node_id] = component

    parts_by_node_id = {}
    part_rows = nodes_df[nodes_df["node_type"] == "part"].sort_values("name")
    for _, row in part_rows.iterrows():
        part_node_id = str(row["node_id"])
        parent_info = part_parent_lookup.get(part_node_id)
        if not parent_info:
            continue
        component = components_by_node_id.get(parent_info["component_node_id"])
        if not component:
            continue

        part = Part.objects.create(
            node_id=part_node_id,
            part_name=str(row.get("name") or part_node_id),
            part_description=f"Loaded from node {part_node_id}",
            part_number=part_node_id,
            component=component,
            date_req=_parse_optional_datetime(row.get("need_by_date")) or datetime.now(),
            criticality=max(0, _safe_int(_safe_float(row.get("criticality"), 0) * 100)),
            quantity=max(1, parent_info["quantity"]),
            NAIC_code="",
            HS_code="",
        )
        parts_by_node_id[part_node_id] = part

    materials_by_node_id = {}
    material_rows = nodes_df[nodes_df["node_type"] == "raw_material"].sort_values("name")
    for _, row in material_rows.iterrows():
        material_node_id = str(row["node_id"])
        parent_info = material_parent_lookup.get(material_node_id)
        if not parent_info:
            continue
        part = parts_by_node_id.get(parent_info["part_node_id"])
        if not part:
            continue

        material = Material.objects.create(
            node_id=material_node_id,
            material_name=str(row.get("name") or material_node_id),
            material_description=f"Loaded from node {material_node_id}",
            part=part,
            quantity=max(1, parent_info["quantity"]),
            date_req=_parse_optional_datetime(row.get("need_by_date")) or datetime.now(),
            criticality=max(0, _safe_int(_safe_float(row.get("criticality"), 0) * 100)),
        )
        materials_by_node_id[material_node_id] = material

    component_supplier_count = 0
    part_supplier_count = 0
    material_supplier_count = 0

    for component_node_id, component in components_by_node_id.items():
        for supplier in supplier_options.get(component_node_id, []):
            ComponentSupplier.objects.create(
                component=component,
                supplier_node_id=str(supplier.get("supplier_node_id") or ""),
                edge_type=str(supplier.get("edge_type") or ""),
                is_selected=_safe_bool(supplier.get("is_selected")),
                supplier_name=str(supplier.get("supplier_name") or "Unknown"),
                Lat=_safe_float(supplier.get("Lat"), 0.0),
                Lon=_safe_float(supplier.get("Lon"), 0.0),
                country=str(supplier.get("country") or ""),
                NAIC_code="",
                HS_code="",
                production_time_days=max(0, _safe_int(supplier.get("production_time_days"), 0)),
                shipping_time_days=max(0, _safe_int(supplier.get("shipping_time_days"), 0)),
            )
            component_supplier_count += 1

    for part_node_id, part in parts_by_node_id.items():
        for supplier in supplier_options.get(part_node_id, []):
            PartSupplier.objects.create(
                part=part,
                supplier_node_id=str(supplier.get("supplier_node_id") or ""),
                edge_type=str(supplier.get("edge_type") or ""),
                is_selected=_safe_bool(supplier.get("is_selected")),
                supplier_name=str(supplier.get("supplier_name") or "Unknown"),
                Lat=_safe_float(supplier.get("Lat"), 0.0),
                Lon=_safe_float(supplier.get("Lon"), 0.0),
                country=str(supplier.get("country") or ""),
                quality=0,
                delay_risk=max(0, _safe_int(supplier.get("delay_risk"), 0)),
                NAIC_code="",
                HS_code="",
                production_time_days=max(0, _safe_int(supplier.get("production_time_days"), 0)),
                shipping_time_days=max(0, _safe_int(supplier.get("shipping_time_days"), 0)),
            )
            part_supplier_count += 1

    for material_node_id, material in materials_by_node_id.items():
        for supplier in supplier_options.get(material_node_id, []):
            MaterialSupplier.objects.create(
                material=material,
                supplier_node_id=str(supplier.get("supplier_node_id") or ""),
                edge_type=str(supplier.get("edge_type") or ""),
                is_selected=_safe_bool(supplier.get("is_selected")),
                supplier_name=str(supplier.get("supplier_name") or "Unknown"),
                Lat=_safe_float(supplier.get("Lat"), 0.0),
                Lon=_safe_float(supplier.get("Lon"), 0.0),
                country=str(supplier.get("country") or ""),
                quality=0,
                delay_risk=max(0, _safe_int(supplier.get("delay_risk"), 0)),
                NAIC_code="",
                HS_code="",
                production_time_days=max(0, _safe_int(supplier.get("production_time_days"), 0)),
                shipping_time_days=max(0, _safe_int(supplier.get("shipping_time_days"), 0)),
            )
            material_supplier_count += 1

    return [
        ["status", "Loaded vessel case-study data from SC_data_generator"],
        ["nodes_csv", "__vessel_nodes_realistic_case_study_with_dates.csv"],
        ["edges_csv", "__vessel_edges_case_study.csv"],
        ["systems", str(1)],
        ["components", str(len(components_by_node_id))],
        ["parts", str(len(parts_by_node_id))],
        ["materials", str(len(materials_by_node_id))],
        ["component_suppliers", str(component_supplier_count)],
        ["part_suppliers", str(part_supplier_count)],
        ["material_suppliers", str(material_supplier_count)],
    ]


def load_project(request):
    if request.method not in {"GET", "POST"}:
        return JsonResponse({"status": "error", "message": "Unsupported request method."}, status=405)

    try:
        summary_rows = _load_case_study_into_database()
    except FileNotFoundError as exc:
        return render(
            request,
            "mainDash/uploaded_data.html",
            {"data": [["error", f"Missing case-study CSV file: {exc}"]]},
            status=400,
        )
    except Exception as exc:
        return render(
            request,
            "mainDash/uploaded_data.html",
            {"data": [["error", f"Failed to load case-study data: {exc}"]]},
            status=500,
        )

    return render(request, "mainDash/uploaded_data.html", {"data": summary_rows})


def generate_data(request):
    return load_project(request)
    
   

########################################################################
#### Old Dashboard Views ###############################################
########################################################################

def detail(request):
    template = loader.get_template("mainDash/detail.html")
    selected_item_ids = request.GET.getlist('selected_items')
    selected_items = Item.objects.filter(id__in=selected_item_ids)
    
    # Define the start and end dates
    start_date = datetime.now()
    start_date = start_date.replace(tzinfo=timezone.utc)
    date_list = [x[0] for x in selected_items.values_list('date_req').all()]
    print(date_list)
    end_date = max(date_list)

    # Generate the list of month-year dates
    potential_dates = generate_month_year_dates(start_date, end_date)

    # Generate planned order schedule: DEFAULT
    items = {}
    for i in selected_items.values().all() :
        items[i['id']] = {i['date_req'].strftime('%b %Y'): {
            'quantity': i['quantity']
        }}

    table_body = ''
    for i in selected_items.values().all() :
        table_body += f"""<tr><td>""" + str(i['item_description']) + f"""</td>
                <td class="item-quantity">""" + str(i['quantity']) + f"""</td>
                <td>""" + str(i['criticality']) + f"""</td>
                <td>""" + str(i['date_req'].strftime('%d %b %Y')) + f"""</td>
            """
        for d in potential_dates :
            if d in items[i['id']] :
                table_body += f"""<td>""" + str(items[i['id']][d]['quantity']) + f"""</td>
                
            """
            else :
                table_body += f"""<td></td>
            """
        table_body += f"""</tr>"""

    # Generate planned order schedule: ALTERNATE
    items_alt = {}
    for i in selected_items.values().all() :
        # Define the start and end dates
        single_end_date = i['date_req']

        potential_purchase_dates = generate_month_year_dates(start_date, single_end_date)
        remaining_quantity = i['quantity']
        ordered_dates = random.sample(potential_purchase_dates, len(potential_purchase_dates))
        items_alt[i['id']] = {}
        k = 0
        while remaining_quantity > 0 :
            if k < len(ordered_dates) - 1:
                 quantity_purchased = random.randint(1, remaining_quantity)
            else :
                quantity_purchased = remaining_quantity
            items_alt[i['id']][ordered_dates[k]] = {
                'quantity': quantity_purchased
            }
            remaining_quantity -= quantity_purchased
            k += 1
    
    table_body_alt = ''
    for i in selected_items.values().all() :
        table_body_alt += f"""<tr><td>""" + str(i['item_description']) + f"""</td>
                <td class="item-quantity">""" + str(i['quantity']) + f"""</td>
                <td>""" + str(i['criticality']) + f"""</td>
                <td>""" + str(i['date_req'].strftime('%d %b %Y')) + f"""</td>
            """
        for d in potential_dates :
            if d in items_alt[i['id']] :
                table_body_alt += f"""<td>""" + str(items_alt[i['id']][d]['quantity']) + f"""</td>
                
            """
            else :
                table_body_alt += f"""<td></td>
            """
        table_body_alt += f"""</tr>"""

    # Get commodity data
   
    # Replace with your FRED API key
    api_key = os.environ.get("FRED_API_KEY")
    image_urls = []

    for i in selected_items.values().all() :

        # Specify the series ID for plastic pipes
        series_id = commodity_series_mapping[i['item_description']]
        print(i['item_description'])

        # Construct the API URL
        api_url = f"https://api.stlouisfed.org/fred/series/observations?series_id={series_id}&api_key={api_key}&file_type=json"

        # Make the API request
        response = requests.get(api_url)
        data = response.json()

        # Extract relevant data points
        if "observations" not in data or not data["observations"]:
            continue
        else :
            observations = data["observations"]
            dates = np.asarray([o['date'] for o in observations], dtype='datetime64[s]')
            values = [o['value'] for o in observations]
            values = ['nan' if v == '.' else v for v in values]
            values = np.asarray(values, dtype=float)

            # Create a line chart
            #plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m/%d/%Y'))
            fig, ax = plt.subplots()
            sns.scatterplot(x = dates, y = values)
            plt.xlabel('Time')
            plt.ylabel('Producer Price Index')
            plt.title(('Producer price index for ' + i['item_description']).title())
            plt.xticks(rotation=45)
            fig.set_tight_layout(True)

            # Save the chart to a buffer
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            image_urls.append(base64.b64encode(buffer.read()).decode())

    context = {
        "selected_items": selected_items,
        "potential_dates": potential_dates,
        "table_body": table_body,
        "table_body_alt": table_body_alt, 
        "image_urls": image_urls
    }

    return HttpResponse(template.render(context, request))

class CSVUploadFormSuppliers(forms.Form):
    csv_file = forms.FileField()

class CSVUploadFormBOM(forms.Form):
    csv_file = forms.FileField()
