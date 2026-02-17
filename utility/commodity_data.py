import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get FRED API key from environment variables
api_key = os.environ.get("FRED_API_KEY")

if not api_key:
    print("Warning: FRED_API_KEY not found in environment variables")
    print("Please set FRED_API_KEY in your .env file")
    exit(1)

# Specify the series ID for plastic pipes
series_id = "PCU326122326122"

# Construct the API URL
api_url = f"https://api.stlouisfed.org/fred/series/observations?series_id={series_id}&api_key={api_key}&file_type=json"

# Make the API request
response = requests.get(api_url)
data = response.json()

# Extract relevant data points
observations = data["observations"]
for observation in observations:
    date = observation["date"]
    value = observation["value"]
    print(f"Date: {date}, Value: {value}")