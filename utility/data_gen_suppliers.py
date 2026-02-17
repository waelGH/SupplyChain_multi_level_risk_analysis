import csv
from faker import Faker
import random
from common_data import states_abbreviations, industry_naics, state_bounding_boxes

# Create a Faker instance
fake = Faker()

# Generate fake supplier data
def generate_supplier():
    name = fake.company().replace(',', '')
    naics = random.choice(list(industry_naics.values()))[0]
    state = random.choice(list(states_abbreviations.values()))
    lat = random.uniform(state_bounding_boxes[state]['lat_min'], state_bounding_boxes[state]['lat_max'])
    lon = random.uniform(state_bounding_boxes[state]['lon_min'], state_bounding_boxes[state]['lon_max'])
    quality = random.randint(0, 6)
    delay_risk = random.randint(0, 6)

    return [name, naics, state, lat, lon, quality, delay_risk]

# Number of fake suppliers to generate
num_suppliers = 100

# Generate supplier data and write to CSV
with open('mock_supplier_data.csv', 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(["Supplier Name", "NAICS Code", "State", "Lat", "Lon", "Quality", "Delay Risk"])

    for _ in range(num_suppliers):
        supplier_data = generate_supplier()
        csvwriter.writerow(supplier_data)

print(f"{num_suppliers} fake suppliers data has been generated and saved in 'mock_supplier_data.csv'.")
