import csv
import random
from faker import Faker
import datetime
from common_data import industry_commodities, commodity_series_mapping, industry_naics

# Create a Faker instance
fake = Faker()

# Generate fake item data
def generate_item(item_number):
    random_industry = random.choice(industries)
    naics = industry_naics[random_industry][0]
    random_part = random.choice(industry_commodities[random_industry])
    quantity = random.randint(1, 20)
    criticality = random.randint(1, 6)
    due_date = fake.date_between(datetime.date.today() + datetime.timedelta(days=365), datetime.date.today() + datetime.timedelta(days=365*2))

    return [item_number, random_part, quantity, criticality, naics, due_date]

# Define the list of industries
industries = list(industry_commodities.keys())

# Randomly select industries and parts/commodities
num_items_to_procure = 50  # Number of items to procure

# Generate BOM data and write to CSV
with open('mock_bom_data.csv', 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(["Item Number", "Item", "Quantity", "Criticality",  "NAICS Code", "Due Date"])

    for i in range(num_items_to_procure):
        item_data = generate_item(i+1)
        csvwriter.writerow(item_data)

print(f"{num_items_to_procure} fake BOM data has been generated and saved in 'mock_bom_data.csv'.")