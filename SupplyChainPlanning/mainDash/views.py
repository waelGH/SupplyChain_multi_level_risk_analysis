# Standard library imports
import base64
import io
import json
import math
import os
import random
import time
import warnings
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from io import TextIOWrapper

# Third-party imports
import gdelt
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
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
from django.template import loader

# Local imports
from mainDash.static.mainDash.commodity_data import commodity_series_mapping
from .models import Case_system, Part, Component, PartSupplier, Material, MaterialSupplier, ComponentSupplier

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
    Calculate a risk score from the extracted GDELT data
    The risk score is approximation of possible disruptions
    It takes into account: 
        1) number of negative events
        2) number of negative events mentions
        3) qualitative analysis of articles titles/content
    """ 
    
    nb_events = 0
    events_tone = 0
    impact = 0
    for index, row in filtered_event_df.iterrows():
        globaleventid = row['globaleventid']
        avgtone = row['avgtone']
        numarticles = row['numarticles']
        sourceurl = row['sourceurl']
        GoldsteinScale = row['goldsteinscale']
        cameocodedescription = row['cameocodedescription']
        
        # print('-------------------------')
        # print(globaleventid)
        # print(avgtone)
        # print(numarticles)
        # print(sourceurl)
        # print(GoldsteinScale)
        # print(cameocodedescription)
        # print('-------------------------')   
        
        # Example usage
        page_text = extract_text_from_url(sourceurl)
        
        # calculate
        nb_events = nb_events + 1
        events_tone = events_tone + avgtone
        impact = impact + GoldsteinScale
        
    #average tone and impact
    if nb_events == 0:
        avg_tone = 0
        avg_impact = 0
    else:
        avg_tone = events_tone/nb_events
        avg_impact = impact/nb_events

    print('average tone',avg_tone)
    print('average impact',avg_impact)
    
    risk_score = (avg_tone + avg_impact) / 2
        
    return risk_score

def analyze_supplier_risk_from_news_workflow(supplier_name,supplier_lat, supplier_lon): 
    # Transform lat,long pair of the supplier into an address
    geolocator = Nominatim(user_agent="geoapi")
    location = geolocator.reverse((supplier_lat, supplier_lon), language='en')
    print('Supplier Location.....',location)
    print('--------------------------')

    if location:
        supplier_address = location.raw.get('address', {})
        supplier_city = supplier_address.get('city', None)
        supplier_town = supplier_address.get('town', None)
        supplier_state = supplier_address.get('state', None)
        supplier_country = supplier_address.get('country', None)
        
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
    print("The number of GDELT reports in the last 30 days is", len(Last_reports)) 
    
    if (len(Last_reports) > 0): 
        ## Filter events by latitude and longitude ##
        filtered_df = filter_events_within_radius(Last_reports, supplier_lat, supplier_lon, radius_miles=50)
        
        ## Calculate risk score from collected events
        risk_score_from_gdelt = calculate_risk_score(filtered_df)
        print('RISK score for this item.......',risk_score_from_gdelt)
        risk_score = risk_score_from_gdelt
    else: 
        print('No report detected.....')
        risk_score = 0

    return risk_score


##############################################################
################# Structures/classes used in analysis ########
##############################################################
class Node:
    def __init__(self, name, tier, suppliers, due_date, quantity=0):
        self.tier = tier                  # "system","component", "part","raw_material"
        self.name = name                  # name of the node
        self.supplier =suppliers          # list of possible suppliers 
        self.quantity = quantity          # Qty needed
        self.due_date = due_date          # due date for the part/material
        self.children = []                # list of sub-nodes (parts or materials)
    
    def add_child(self, child_node):
        self.children.append(child_node)

def print_tree(node, level=0):
    print("   " * level + f"- {node.tier.upper()}: {node.name}")
    print("   " * level + f"  Suppliers: {list(node.supplier.keys()) if isinstance(node.supplier, dict) else node.supplier}")
    for child in node.children:
        print_tree(child, level+1)

# Function to traverse the tree and select one supplier randomly for each node to create a production chain
def select_random_suppliers(node, selected=None):
    if selected is None:
        selected = {}

    # if the node has suppliers, pick one randomly
    if node.supplier:  
        chosen = random.choice(list(node.supplier.items()))
        selected[node.name] = chosen
        # Example print
        #print(f"Node: {node.name} (Tier: {node.tier}) → Supplier chosen: {chosen}")

    # loop through children
    for child in node.children:
        select_random_suppliers(child, selected)

    return selected

def build_selected_plan_tree(node, selected_chain):
    selected_entry = selected_chain.get(node.name)
    selected_supplier = selected_entry[0] if selected_entry else None
    supplier_info = selected_entry[1] if selected_entry and len(selected_entry) > 1 else None

    return {
        "name": node.name,
        "tier": node.tier,
        "selected_supplier": selected_supplier,
        "supplier_info": supplier_info,
        "children": [build_selected_plan_tree(child, selected_chain) for child in node.children]
    }

def scan_risk_for_nodes(node,production_chain,risk_score=None):
    if risk_score is None:
        risk_score = {}

    print('--------------------------')
    print(production_chain.keys())
    print('--------------------------')

    print('analyze risk for node',node.name, node.tier)
    node_name = node.name
    node_tier = node.tier

    risk_from_news= 0
    cyber_risk_score = 0

    ## for parts and raw materials, risk is calculated based on the following:
    ## 1) Scan supplier location (news)
    ## 2) scan supplier name (news)
    ## 3) scan cyber thtreats associated with the name (only for parts)
    ## 4) aggregate the risk score
    if node_tier == 'part':
        if node_name in production_chain.keys(): 
            node_supplier_info = production_chain[node_name]
            supplier_name = node_supplier_info[0]
            supplier_lat = node_supplier_info[1]['Lat']
            supplier_lon = node_supplier_info[1]['Lon']
            supplier_country = node_supplier_info[1]['country']

            print('Scan physical risk based on supplier',supplier_name,'location')
            risk_from_news = analyze_supplier_risk_from_news_workflow(supplier_name,supplier_lat, supplier_lon)
            print('risk from news (average of tone and impact)',risk_from_news)

            print('Scan cyber risk based on part',node_name)
            # from part: get possible CPEs
            part_valid_cpes = get_valid_cpes_for_component(node_name)

            # # Main collection loop
            all_cve_data = []
            for cpe in part_valid_cpes:
                print(f"Querying CVEs for {cpe}...")
                cve_results = get_cves_for_cpe(cpe)
                
                if not cve_results:  # Empty list check
                    print("⚠️ No results, skipping...")
                
                all_cve_data.extend(cve_results)
                time.sleep(0.6)  # To stay under rate limits
        
            cyber_risk_score = len(all_cve_data)  # Simple metric: number of CVEs found  
            print('cyber risk score (number of CVEs found)',cyber_risk_score)   
        else: 
            print("No supplier info found for part", node_name)
    elif node_tier == 'raw_material':
        print('Raw material level - No risk calculated')
        # if node_name in production_chain.keys(): 
        #     node_supplier_info = production_chain[node_name]
        #     supplier_name = node_supplier_info[0]
        #     supplier_lat = node_supplier_info[1]['Lat']
        #     supplier_lon = node_supplier_info[1]['Lon']
        #     supplier_country = node_supplier_info[1]['country']

        #     print('Scan physical risk based on supplier',supplier_name,'location')
        #     risk_from_news = analyze_supplier_risk_from_news_workflow(supplier_name,supplier_lat, supplier_lon)
        #     print('risk from news (average of tone and impact)',risk_from_news)

        #     print('Scan cyber risk based on part',node_name)
        #     # from part: get possible CPEs
        #     part_valid_cpes = get_valid_cpes_for_component(node_name)

        #     # # Main collection loop
        #     all_cve_data = []
        #     for cpe in part_valid_cpes:
        #         print(f"Querying CVEs for {cpe}...")
        #         cve_results = get_cves_for_cpe(cpe)
                
        #         if not cve_results:  # Empty list check
        #             print("⚠️ No results, skipping...")
                
        #         all_cve_data.extend(cve_results)
        #         time.sleep(0.6)  # To stay under rate limits
        #     cyber_risk_score = len(all_cve_data)  # Simple metric: number of CVEs found  
        #     print('cyber risk score (number of CVEs found)',cyber_risk_score)   
        # else: 
        #     print("No supplier info found for this raw material", node_name)

    elif node_tier == 'component':
        print("Component level - no risk calculated")
    else: 
        print("System level - no risk calculated")

    risk_score[node_name] = {
        "tier": node_tier,
        "risk_from_news": risk_from_news,
        "cyber_risk_score": cyber_risk_score
    }

    # loop through children
    for child in node.children:
        scan_risk_for_nodes(child, production_chain, risk_score)

    return risk_score


########################################################################
#### New Dashboard Views ###############################################
########################################################################
# Index View for the dashboard (August 2025) 
def index_case_study(request):
    template = loader.get_template("mainDash/index_case_study.html")
    uploaded_parts = Part.objects.all()
    selected_part_id = request.GET.get('selected_part')
    suppliers = None

    if selected_part_id:
        try:
            selected_part = Part.objects.get(id=selected_part_id)
            suppliers = PartSupplier.objects.filter(part=selected_part)
        except Part.DoesNotExist:
            suppliers = None

    context = {
        "uploaded_parts": uploaded_parts,
        "selected_part_id": selected_part_id,
        "suppliers": suppliers,
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

    ############# Upload data #######################
    uploaded_case_systems = Case_system.objects.all()
    uploaded_components = Component.objects.all()
    uploaded_material_suppliers = MaterialSupplier.objects.all()
    uploaded_parts = Part.objects.all()
    uploaded_part_suppliers = PartSupplier.objects.all()
    uploaded_materials = Material.objects.all()
    uploaded_material_suppliers = MaterialSupplier.objects.all()

    ############## Populate the supply chain tree structure #######################
    # Define root node (system)
    if uploaded_case_systems.exists():
        case = uploaded_case_systems.first()
        vessel_system = Node("vessel", "system",{},0)

    # define component nodes
    ls_components = []
    for comp in uploaded_components:
        if comp.case_system == case:
            # determine the list of suppliers for this component
            comp_suppliers = ComponentSupplier.objects.filter(component=comp)
            ls_suppliers = {}
            for sup in comp_suppliers:
                ls_suppliers[sup.supplier_name] = {
                    "Lat": sup.Lat,
                    "Lon": sup.Lon,
                    "country": sup.country
                }
            # add to the components list
            ls_components.append(Node(comp.component_name, "component",ls_suppliers,None,0))

    # define part nodes and raw material nodes
    ls_parts = []
    for part in uploaded_parts:
        if part.component in uploaded_components:
            # determine the list of suppliers for this part
            part_suppliers = PartSupplier.objects.filter(part=part)
            ls_suppliers = {}
            for sup in part_suppliers:
                ls_suppliers[sup.supplier_name] = {
                    "Lat": sup.Lat,
                    "Lon": sup.Lon,
                    "country": sup.country,
                    "NAIC_code": sup.NAIC_code,
                    "HS_code": sup.HS_code,
                    "production_time_days": sup.production_time_days,
                    "shipping_time_days": sup.shipping_time_days
                }
            # add to the components list
            part_node = Node(part.part_name, "part",ls_suppliers,part.date_req,part.quantity)
            
            # add raw materials as children of the part
            materials = Material.objects.filter(part=part)
            for mat in materials:
                # determine the list of suppliers for this material
                mat_suppliers = MaterialSupplier.objects.filter(material=mat)
                ls_suppliers = {}
                for sup in mat_suppliers:
                    ls_suppliers[sup.supplier_name] = {
                        "Lat": sup.Lat,
                        "Lon": sup.Lon,
                        "country": sup.country,
                        "NAIC_code": sup.NAIC_code,
                        "HS_code": sup.HS_code,
                        "production_time_days": sup.production_time_days,
                        "shipping_time_days": sup.shipping_time_days
                    }
                mat_node = Node(mat.material_name, "raw_material",ls_suppliers,mat.date_req,mat.quantity)
                part_node.add_child(mat_node)
                
            # add the part node to the corresponding component
            for comp_node in ls_components:
                if comp_node.name == part.component.component_name:
                    comp_node.add_child(part_node)

    # add children to the root noded
    for comp in ls_components:
        if comp.children:  # only add components that have parts
            vessel_system.add_child(comp)
    ####################################################################################

    # print('--------------------------')
    # print_tree(vessel_system)
    # print('--------------------------')

    selected_production_chain = select_random_suppliers(vessel_system)
    request.session['selected_production_chain'] = json.dumps(selected_production_chain)
    selected_plan_tree = build_selected_plan_tree(vessel_system, selected_production_chain)
    #print('Selected production chain:',selected_production_chain)

    return JsonResponse({
        "status": "success",
        "plan": selected_production_chain,
        "plan_tree": selected_plan_tree
    })

def simulate_plan(request):
    """
    Simulate the generated production plan by analyzing risks for each supplier.
    """   
    
    # Retrieve from session and deserialize
    selected_chain_json = request.session.get('selected_production_chain')
    print('Selected production plan from session:',selected_chain_json)
    if not selected_chain_json:
        return JsonResponse({"status": "error", "message": "No production plan found in session."})

    selected_production_chain = json.loads(selected_chain_json)

    ############## Populate the supply chain tree structure #######################
    uploaded_case_systems = Case_system.objects.all()
    uploaded_components = Component.objects.all()
    uploaded_material_suppliers = MaterialSupplier.objects.all()
    uploaded_parts = Part.objects.all()
    uploaded_part_suppliers = PartSupplier.objects.all()
    uploaded_materials = Material.objects.all()
    uploaded_material_suppliers = MaterialSupplier.objects.all()
    # Define root node (system)
    if uploaded_case_systems.exists():
        case = uploaded_case_systems.first()
        vessel_system = Node("vessel", "system",{},0)

    # define component nodes
    ls_components = []
    for comp in uploaded_components:
        if comp.case_system == case:
            # determine the list of suppliers for this component
            comp_suppliers = ComponentSupplier.objects.filter(component=comp)
            ls_suppliers = {}
            for sup in comp_suppliers:
                ls_suppliers[sup.supplier_name] = {
                    "Lat": sup.Lat,
                    "Lon": sup.Lon,
                    "country": sup.country
                }
            # add to the components list
            ls_components.append(Node(comp.component_name, "component",ls_suppliers,None,0))

    # define part nodes and raw material nodes
    ls_parts = []
    for part in uploaded_parts:
        if part.component in uploaded_components:
            # determine the list of suppliers for this part
            part_suppliers = PartSupplier.objects.filter(part=part)
            ls_suppliers = {}
            for sup in part_suppliers:
                ls_suppliers[sup.supplier_name] = {
                    "Lat": sup.Lat,
                    "Lon": sup.Lon,
                    "country": sup.country,
                    "NAIC_code": sup.NAIC_code,
                    "HS_code": sup.HS_code,
                    "production_time_days": sup.production_time_days,
                    "shipping_time_days": sup.shipping_time_days
                }
            # add to the components list
            part_node = Node(part.part_name, "part",ls_suppliers,part.date_req,part.quantity)
            
            # add raw materials as children of the part
            materials = Material.objects.filter(part=part)
            for mat in materials:
                # determine the list of suppliers for this material
                mat_suppliers = MaterialSupplier.objects.filter(material=mat)
                ls_suppliers = {}
                for sup in mat_suppliers:
                    ls_suppliers[sup.supplier_name] = {
                        "Lat": sup.Lat,
                        "Lon": sup.Lon,
                        "country": sup.country,
                        "NAIC_code": sup.NAIC_code,
                        "HS_code": sup.HS_code,
                        "production_time_days": sup.production_time_days,
                        "shipping_time_days": sup.shipping_time_days
                    }
                mat_node = Node(mat.material_name, "raw_material",ls_suppliers,mat.date_req,mat.quantity)
                part_node.add_child(mat_node)
                
            # add the part node to the corresponding component
            for comp_node in ls_components:
                if comp_node.name == part.component.component_name:
                    comp_node.add_child(part_node)

    # add children to the root noded
    for comp in ls_components:
        if comp.children:  # only add components that have parts
            vessel_system.add_child(comp)
    ####################################################################################

    # Scan over the production chain and analyze risk for each supplier
    calculated_risk_scores = scan_risk_for_nodes(vessel_system,selected_production_chain)
    print('--------------------------')
    print('RISK analysis for the production chain')
    print(calculated_risk_scores)
    print('--------------------------')

    risk_dict= {'risk_scores': 0,'delays':0,'summary':0}   

    return JsonResponse({"status": "success", "riskScores": risk_dict})

# def run_simulation(request):
#     template = loader.get_template("mainDash/run_simulation.html")

#     #################################################
#     ############# Upload data #######################
#     #################################################
#     # Upload all data from the database
#     uploaded_case_systems = Case_system.objects.all()
#     uploaded_components = Component.objects.all()
#     uploaded_material_suppliers = MaterialSupplier.objects.all()
#     uploaded_parts = Part.objects.all()
#     uploaded_part_suppliers = PartSupplier.objects.all()
#     uploaded_materials = Material.objects.all()
#     uploaded_material_suppliers = MaterialSupplier.objects.all()

#     # Populate the supply chain tree structure
#     # Define root node (system)
#     if uploaded_case_systems.exists():
#         case = uploaded_case_systems.first()
#         vessel_system = Node("vessel", "system",{},0)

#     # define component nodes
#     ls_components = []
#     for comp in uploaded_components:
#         if comp.case_system == case:
#             # determine the list of suppliers for this component
#             comp_suppliers = ComponentSupplier.objects.filter(component=comp)
#             ls_suppliers = {}
#             for sup in comp_suppliers:
#                 ls_suppliers[sup.supplier_name] = {
#                     "Lat": sup.Lat,
#                     "Lon": sup.Lon,
#                     "country": sup.country
#                 }
#             # add to the components list
#             ls_components.append(Node(comp.component_name, "component",ls_suppliers,None,0))

#     # define part nodes and raw material nodes
#     ls_parts = []
#     for part in uploaded_parts:
#         if part.component in uploaded_components:
#             # determine the list of suppliers for this part
#             part_suppliers = PartSupplier.objects.filter(part=part)
#             ls_suppliers = {}
#             for sup in part_suppliers:
#                 ls_suppliers[sup.supplier_name] = {
#                     "Lat": sup.Lat,
#                     "Lon": sup.Lon,
#                     "country": sup.country,
#                     "NAIC_code": sup.NAIC_code,
#                     "HS_code": sup.HS_code,
#                     "production_time_days": sup.production_time_days,
#                     "shipping_time_days": sup.shipping_time_days
#                 }
#             # add to the components list
#             part_node = Node(part.part_name, "part",ls_suppliers,part.date_req,part.quantity)
            
#             # add raw materials as children of the part
#             materials = Material.objects.filter(part=part)
#             for mat in materials:
#                 # determine the list of suppliers for this material
#                 mat_suppliers = MaterialSupplier.objects.filter(material=mat)
#                 ls_suppliers = {}
#                 for sup in mat_suppliers:
#                     ls_suppliers[sup.supplier_name] = {
#                         "Lat": sup.Lat,
#                         "Lon": sup.Lon,
#                         "country": sup.country,
#                         "NAIC_code": sup.NAIC_code,
#                         "HS_code": sup.HS_code,
#                         "production_time_days": sup.production_time_days,
#                         "shipping_time_days": sup.shipping_time_days
#                     }
#                 mat_node = Node(mat.material_name, "raw_material",ls_suppliers,mat.date_req,mat.quantity)
#                 part_node.add_child(mat_node)
                
#             # add the part node to the corresponding component
#             for comp_node in ls_components:
#                 if comp_node.name == part.component.component_name:
#                     comp_node.add_child(part_node)

#     # add children to the root noded
#     for comp in ls_components:
#         if comp.children:  # only add components that have parts
#             vessel_system.add_child(comp)

#     # print('--------------------------')
#     # print_tree(vessel_system)
#     # print('--------------------------')

#     #################################################
#     ############# Pick a production chain ###########
#     #################################################
#     selected_production_chain = select_random_suppliers(vessel_system)

#     # Scan over the production chain and analyze risk for each supplier
#     calculated_risk_scores = scan_risk_for_nodes(vessel_system,selected_production_chain)
#     print('--------------------------')
#     print('RISK analysis for the production chain')
#     print(calculated_risk_scores)
#     print('--------------------------')

#     context = {}
#     return HttpResponse(template.render(context, request))


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


def scan_cyber_layer(request):
    template = loader.get_template("mainDash/scan_cyber_layer.html")
    
    # Uplaoad data to show in the drowpdown select
    components = Component.objects.all()
    Parts = Part.objects.all()
    PartSuppliers = PartSupplier.objects.all()
    materials = Material.objects.all()
    MaterialsSupplier= MaterialSupplier.objects.all()

    # Pass the data to the template context
    context = {
        "components": components,
        "parts": Parts,
        "part_suppliers": PartSuppliers,
        "materials": materials,
        "material_suppliers": MaterialsSupplier,
    }

    return render(request, "mainDash/scan_cyber_layer.html", context)

def scan_supply_chain(request):
    template = loader.get_template("mainDash/supply_chain_analysis.html")
    context = {}
    return HttpResponse(template.render(context, request))

def perform_analysis_view(request):
    # Example logic for analysis
    scenario = request.GET.get('scenario', None)

    if scenario:
        scenario_information = { 
            'case_name': 'Vessel',
            'part_name': '',
            'component_name': '',
            'part_NAIC': '',
            'part_HS': '',
            'part_supplier_name': '',
            'part_supplier_lat': 0,
            'part_supplier_lon': 0,
            'part_supplier_NAIC': '',
            'part_supplier_HS': '',
            'material_name': '',
            'material_supplier_name': '',
            'material_supplier_lat': 0,
            'material_supplier_lon': 0,
            'material_supplier_NAIC': '',
            'material_supplier_HS': ''
        }
        ######## Perform some analysis based on the scenario ########
        ######## Select a production chain      #####################
        parts = Part.objects.all()
        if not parts.exists():
            return JsonResponse({"status": "error", "message": "No parts available."})
        selected_part = random.choice(parts)

        # save part information
        scenario_information['part_name'] = selected_part.part_name
        scenario_information['component_name'] = selected_part.component.component_name
        scenario_information['part_NAIC'] = selected_part.NAIC_code
        scenario_information['part_HS'] = selected_part.HS_code

        
        # Get related PartSupplier(s)
        part_suppliers = PartSupplier.objects.filter(part=selected_part)
        
        # Check if there are any part suppliers
        if part_suppliers.exists():
            # Select a random part supplier
            random_part_supplier = random.choice(part_suppliers)
            print("Random Part Supplier:", random_part_supplier)
            scenario_information['part_supplier_name'] = random_part_supplier.supplier_name
            scenario_information['part_supplier_lat'] = random_part_supplier.Lat
            scenario_information['part_supplier_lon'] = random_part_supplier.Lon
            scenario_information['part_supplier_NAIC'] = random_part_supplier.NAIC_code
            scenario_information['part_supplier_HS'] = random_part_supplier.HS_code

        else:
            print("No part suppliers found for the selected part.")


        # Get related Material(s)
        materials = Material.objects.filter(part=selected_part)
        # Check if there are any materials
        if materials.exists():
            # Select a random material
            random_material = random.choice(materials)
            print("Random Material:", random_material)  
            scenario_information['material_name'] = random_material.material_name

            # Get all suppliers related to the random material
            material_suppliers = MaterialSupplier.objects.filter(material=random_material)

            
            if material_suppliers.exists():
                # Select a random material supplier
                random_material_supplier = random.choice(material_suppliers)
                print("Random Material Supplier:", random_material_supplier)
                scenario_information['material_supplier_name'] = random_material_supplier.supplier_name
                scenario_information['material_supplier_lat'] = random_material_supplier.Lat
                scenario_information['material_supplier_lon'] = random_material_supplier.Lon
                scenario_information['material_supplier_NAIC'] = random_material_supplier.NAIC_code
                scenario_information['material_supplier_HS'] = random_material_supplier.HS_code

            else:
                print("No material suppliers found for the selected material.")
                random_material_supplier_data = None
        else:
            print("No materials found for the selected part.")

        print("Scenario Information:", scenario_information)
        
        #############################################################################
        # Perform scan from the news around the selected production chain
        #############################################################################
        # Force the selection of a specific production chain
        part_name = 'Shafts/Propellers'
        partID = 9
        part_supplier_name = 'Raytheon Technologies'
        Material_name = 'Aluminum'
        Material_supplier_name = 'Alcoa'
        forced_selected_part = Part.objects.filter(part_name=part_name).first()
        forced_selected_part_supplier = PartSupplier.objects.filter(part=forced_selected_part, supplier_name=part_supplier_name).first()
        forced_selected_material = Material.objects.filter(part=forced_selected_part, material_name=Material_name).first()
        forced_selected_material_supplier = MaterialSupplier.objects.filter(material=forced_selected_material, supplier_name=Material_supplier_name).first()
        print('Forced selected part:', forced_selected_part)
        print('Forced selected part supplier:', forced_selected_part_supplier)
        print('Forced selected material:', forced_selected_material)
        print('Forced selected material supplier:', forced_selected_material_supplier)
        print('---------------------------')

        #############################################################################
        #############################################################################

        # Scan part supplier
        print('Scanning potential disruptions for part.....',forced_selected_part.part_name)
        r = analyze_supplier_risk_from_news_workflow(forced_selected_part_supplier.supplier_name,forced_selected_part_supplier.Lat, forced_selected_part_supplier.Lon)
        print('Risk score from news: ', r)
        
        forced_selected_scenario_data = {
            'part_name': forced_selected_part.part_name,
            'part_supplier_name': forced_selected_part_supplier.supplier_name,
            'material_name': forced_selected_material.material_name,
            'material_supplier_name': forced_selected_material_supplier.supplier_name,
            'part_supplier_lat': forced_selected_part_supplier.Lat,
            'part_supplier_lon': forced_selected_part_supplier.Lon,
            'material_supplier_lat': forced_selected_material_supplier.Lat,
            'material_supplier_lon': forced_selected_material_supplier.Lon
        }

        # Scan part material supplier location
        #print('Scanning potential disruptions for.....',scenario_information['part_supplier_name'])
        #r = analyze_supplier_risk_from_news_workflow(scenario_information['part_supplier_name'],scenario_information['part_supplier_lat'], scenario_information['part_supplier_lon'])
        #print('Risk score from news scan: ', r)
        
        return JsonResponse({
            "status": "success",
            "scenario": scenario,
            "part_name": forced_selected_part.part_name,
            "part_supplier_name": forced_selected_part_supplier.supplier_name,
            "material_name": forced_selected_material.material_name,
            "part_supplier_location": "",
            "risk_score": r,
            "message": f"Risk score calculated for {scenario}.",
            "supplierInfo": {
                "lat": forced_selected_part_supplier.Lat,
                "long": forced_selected_part_supplier.Lon
         }
        })
    else:
        return JsonResponse({"status": "error", "message": "No scenario provided."})    

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

def load_project(request):
    if request.method == 'POST':
        form = CSVUploadFormBOM(request.POST, request.FILES)

        if form.is_valid():
            csv_file = request.FILES['csv_file']

            # read into data frame
            df = pd.read_csv(TextIOWrapper(csv_file, encoding='utf-8'))

            # Add new system object if it does not exist
            system_name = "Vessel_System"
            system_obj, _ = Case_system.objects.get_or_create(
                case_name=system_name,
                case_description="System for Vessel Case Study",
                date_created=datetime.now()
            )

            # Loop over DataFrame rows
            for _, row in df.iterrows():
                tier = row['tier'].strip()

                print('tier:', tier)
                print(row)
                print('-------------------')

                if tier == 'Component':
                    component_name = row['component'].strip()
                    supplied_item = row['supplied_item'].strip()
                    supplier_name = row['supplier_name'].strip()
                    supplier_country = row['supplier_country'].strip()
                    supplier_lat = row['supplier_lat']
                    supplier_lon = row['supplier_lon']
                    Production_Lead_Time_Days = int(row['Production_Lead_Time_Days'])
                    Transportation_Time_Days= int(row['Transportation_Time_Days'])
                    component_quantity = int(row['component_quantity'])
                    # Parse date from MM/DD/YY to YYYY-MM-DD
                    try:
                        #component_due_date = datetime.strptime(row['component_due_date'], "%m/%d/%y")
                        component_due_date = datetime.strptime(row['component_due_date'], "%Y-%m-%d")
                        
                    except ValueError:
                        component_due_date = None  # or handle error as needed

                    # If component aready exists, skip to next row
                    try:
                        existing_component = Component.objects.get(component_name=component_name)
                        print(f"Component {component_name} already exists. Skipping.")
                        continue  # Skip to the next row
                    except Component.DoesNotExist:
                        existing_component = None
                        pass  # Component does not exist, proceed to create it

                    if existing_component:
                        ## just add the current supplier ##
                        print(f"Adding supplier {supplier_name} for existing component {component_name}.")
                        supplier_obj, _ = ComponentSupplier.objects.get_or_create( 
                            component = existing_component,
                            supplier_name = supplier_name,
                            Lat = supplier_lat,
                            Lon = supplier_lon,
                            country = supplier_country,
                            production_time_days = Production_Lead_Time_Days,
                            shipping_time_days = Transportation_Time_Days,
                            NAIC_code = "",  # Assuming NAIC code is not provided in the CSV
                            HS_code = "",  # Assuming HS code is not provided in the CSV
                            date_created = datetime.now()
                        )   
                    else: 
                        ## Add new component to the database if not exists + supplier ######
                        print(f"Creating component {component_name} and adding supplier {supplier_name}.")
                        component_obj, _ = Component.objects.get_or_create(
                            component_name=component_name,
                            case_system=system_obj,
                            component_description="Component for Vessel Case Study",
                            date_created=datetime.now()
                        )   

                        supplier_obj, _ = ComponentSupplier.objects.get_or_create( 
                            component = component_obj,
                            supplier_name = supplier_name,
                            Lat = supplier_lat,
                            Lon = supplier_lon,
                            production_time_days = Production_Lead_Time_Days,
                            shipping_time_days = Transportation_Time_Days,
                            country = supplier_country,
                            NAIC_code = "",  # Assuming NAIC code is not provided in the CSV
                            HS_code = "",  # Assuming HS code is not provided in the CSV
                            date_created = datetime.now()
                        )   
                elif tier == 'Part':
                    component_name = row['component'].strip()
                    part_name = row['part'].strip()
                    supplied_item = row['supplied_item'].strip()
                    supplier_name = row['supplier_name'].strip()
                    supplier_country = row['supplier_country'].strip()
                    supplier_lat = row['supplier_lat']
                    supplier_lon = row['supplier_lon']
                    Production_Lead_Time_Days = int(row['Production_Lead_Time_Days'])
                    Transportation_Time_Days= int(row['Transportation_Time_Days'])
                    part_quantity = int(row['part_quantity'])
                    # Parse date from MM/DD/YY to YYYY-MM-DD
                    try:
                        part_due_date_ = datetime.strptime(row['part_due_date'], "%m/%d/%y")
                        #part_due_date_ = datetime.strptime(row['part_due_date'], "%Y-%m-%d")
                    except ValueError:
                        part_due_date_ = None  # or handle error as needed

                    # If part already exists, skip to next row
                    try:
                        existing_part = Part.objects.get(part_name=part_name)
                        print(f"Part {part_name} already exists. Skipping.")
                        continue  # Skip to the next row
                    except Part.DoesNotExist:
                        existing_part = None
                        pass  # Part does not exist, proceed to create it  
                        

                    if existing_part:
                        ## just add the current supplier ##
                        supplier_obj, _ = PartSupplier.objects.get_or_create( 
                            part = existing_part,
                            supplier_name = supplier_name,
                            Lat = supplier_lat,
                            Lon = supplier_lon,
                            country = supplier_country,
                            quality = 0,
                            delay_risk = 0,
                            production_time_days = Production_Lead_Time_Days,
                            shipping_time_days = Transportation_Time_Days,
                            NAIC_code = "",  # Assuming NAIC code is not provided in the CSV
                            HS_code = "",  # Assuming HS code is not provided in the CSV
                            date_created = datetime.now(),
                        )
                    else: 
                        # Find component object
                        try:
                            component_obj = Component.objects.get(component_name=component_name)
                        except Component.DoesNotExist:
                            component_obj = None        

                        # Create a new part and its supplier
                        if component_obj:
                            print(f"Creating part {part_name} under component {component_name}.")
                            new_part = Part(
                                part_number = "",
                                component = component_obj,
                                part_name = part_name,
                                part_description = "part for Vessel Case Study",
                                quantity = part_quantity,
                                criticality = 0,
                                NAIC_code = "",
                                date_req = part_due_date_,
                                HS_code = "",
                                date_created = datetime.now()
                            )
                            # Save the new instance to the database
                            new_part.save()

                            supplier_obj, _ = PartSupplier.objects.get_or_create( 
                                part = new_part,
                                supplier_name = supplier_name,
                                Lat = supplier_lat,
                                Lon = supplier_lon,
                                country = supplier_country,
                                production_time_days = Production_Lead_Time_Days,
                                shipping_time_days = Transportation_Time_Days,
                                NAIC_code = "",  # Assuming NAIC code is not provided in the CSV
                                HS_code = "",  # Assuming HS code is not provided in the CSV
                                date_created = datetime.now()
                            )       

                elif tier == 'RawMaterial':
                    component_name = row['component'].strip()
                    part_name = row['part'].strip()
                    material_name= row['raw_material'].strip()
                    supplied_item = row['supplied_item'].strip()
                    supplier_name = row['supplier_name'].strip()
                    supplier_country = row['supplier_country'].strip()
                    supplier_lat = row['supplier_lat']
                    supplier_lon = row['supplier_lon']
                    Production_Lead_Time_Days = int(row['Production_Lead_Time_Days'])
                    Transportation_Time_Days= int(row['Transportation_Time_Days'])
                    material_quantity = int(row['raw_material_quantity'])
                    # Parse date from MM/DD/YY to YYYY-MM-DD
                    try:     
                        material_due_date = datetime.strptime(row['raw_material_due_date'], "%m/%d/%y")
                        #material_due_date = datetime.strptime(row['raw_material_due_date'], "%Y-%m-%d")
                        
                    except ValueError:     
                        material_due_date = None  # or handle error as needed

                    ## If material already exists, skip to next row ##
                    try:
                        existing_material = Material.objects.get(material_name=material_name)
                        print(f"Material {material_name} already exists. Skipping.")
                        continue  # Skip to the next row
                    except Material.DoesNotExist:
                        existing_material = None
                        pass  # Material does not exist, proceed to create it

                    if existing_material:
                        ## just add the current supplier ##
                        print(f"Adding supplier {supplier_name} for existing material {material_name}.")
                        supplier_obj, _ = MaterialSupplier.objects.get_or_create( 
                            material = existing_material,
                            supplier_name = supplier_name,
                            Lat = supplier_lat,
                            Lon = supplier_lon,
                            country = supplier_country,
                            production_time_days = Production_Lead_Time_Days,
                            shipping_time_days = Transportation_Time_Days,
                            NAIC_code = "",  # Assuming NAIC code is not provided in the CSV
                            HS_code = "",  # Assuming HS code is not provided in the CSV
                            date_created = datetime.now()
                        )
                    else: 
                        # Find part object
                        try:
                            part_obj = Part.objects.get(part_name=part_name)
                        except Part.DoesNotExist:
                            part_obj = None        

                        # Create a new material and its supplier
                        if part_obj:
                            print(f"Creating material {material_name} under part {part_name}.")
                            new_material = Material(
                                part = part_obj,
                                material_name = material_name,
                                material_description = "material for Vessel Case Study",
                                quantity = material_quantity,
                                date_req = material_due_date,
                                criticality = 0,
                                date_created = datetime.now()
                            )
                            # Save the new instance to the database
                            new_material.save()

                            supplier_obj, _ = MaterialSupplier.objects.get_or_create( 
                                material = new_material,
                                supplier_name = supplier_name,
                                Lat = supplier_lat,
                                Lon = supplier_lon,
                                country = supplier_country,
                                production_time_days = Production_Lead_Time_Days,
                                shipping_time_days = Transportation_Time_Days,
                                NAIC_code = "",  # Assuming NAIC code is not provided in the CSV
                                HS_code = "",  # Assuming HS code is not provided in the CSV
                                date_created = datetime.now()
                            )
                        else: 
                            print(f"Part with name {part_name} not found. Skipping material creation.") 
                else:
                    # If tier is not recognized, skip this row
                    continue    

            return render(request, 'mainDash/uploaded_data.html', {'data': []})
        
    else:
        form = CSVUploadFormBOM()

    return render(request, 'mainDash/upload_csv.html', {'form': form, 'form_title': 'Upload Material Data'})
    

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
