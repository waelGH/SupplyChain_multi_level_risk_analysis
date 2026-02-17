icon_colors = [
    'blue', 'green', 'purple', 'orange', 'darkred', 'lightred', 'beige', 'darkblue',
    'darkgreen', 'cadetblue', 'darkpurple', 'white', 'pink', 'lightblue', 'lightgreen',
    'gray', 'black', 'red', 'yellow', 'darkgray', 'lightgray', 'bluegray', 'lightpurple'
]

industry_naics = {
    "Screw, Nut & Bolt Manufacturing": "332710",
    "Iron & Steel Manufacturing": "331110",
    "Hardware Manufacturing": "332510",
    "Shipbuilding": "336611",
    "Boat Building": "336612",
    "Ferrous Metal Foundry": "331511",
    "Metal Pipe and Tube Manufacturing": "331210",
    "Metal Plating & Treating": "332813",
    "Copper Rolling, drawing & extruding": "331420",
    "Wire & Spring": "332618",
    "Coal Mining": "212100",
    "Nuclear Power": "221113",
    "Steel Rolling & drawing": "331221",
    "Mining": "212200",
    "Hydroelectric Power": "221111",
    "Iron Ore Mining": "212210",
    "Oil and Gas Pipeline": "486210",
    "Plastic and Resins Manufacturing": "325211",
    "Paint Manufacturing": "325510",
    "Oil drilling and gas extraction": "211111",
    "Mineral Phosphate Mining": "212392",
    "Ink Manufacturing": "325910",
    "Metal Tank Manufacturing": "332420",
    "Power Tools and Machinery Manufacturing": "333991",
    "Industrial Machinery Manufacturing": "333200",
    "Metalworking machinery": "333512",
    "Aluminum Manufacturing": "331313",
    "Nonferrous Metal Refining": "331419",
    "Engine & turbine Manufacturing": "333611",
    "Ball Bearing Manufacturing": "332991",
    "Metal Wholeselling": "423500",
    "Nonferrous Metal Rolling & Alloying": "331492",
    "Sand & Gravel Mining": "212321",
    "Glass Product Manufacturing": "327200",
    "Plastic Pipes and Parts Manufacturing": "326122",
    "Hose and Belt Manufacturing": "326220"
}

def reverse_dict(dictionary):
    reversed_dict = {value: key for key, value in dictionary.items()}
    return reversed_dict

naics_industry = reverse_dict(industry_naics)

industry_naics_icons = {
    "332710": "fa-wrench",
    "331110": "fa-industry",
    "332510": "fa-wrench",
    "336611": "fa-ship",
    "336612": "fa-ship",
    "331511": "fa-building",
    "331210": "fa-building",
    "332813": "fa-flask",
    "331420": "fa-certificate",
    "332618": "fa-building",
    "212100": "fa-industry",
    "221113": "fa-bolt",
    "331221": "fa-recycle",
    "212200": "fa-industry",
    "221111": "fa-tint",
    "212210": "fa-industry",
    "486210": "fa-ellipsis-h",
    "325211": "fa-flask",
    "325510": "fa-paint-brush",
    "211111": "fa-flask",
    "212392": "fa-industry",
    "325910": "fa-pencil",
    "332420": "fa-industry",
    "333991": "fa-gear",
    "333200": "fa-cogs",
    "333512": "fa-cogs",
    "331313": "fa-industry",
    "331419": "fa-industry",
    "333611": "fa-industry",
    "332991": "fa-cogs",
    "423500": "fa-building",
    "331492": "fa-industry",
    "212321": "fa-industry",
    "327200": "fa-flask-vial",
    "326122": "fa-industry",
    "326220": "fa-industry"
}

industry_naics_colors = {
    "332710": "blue",
    "331110": "green",
    "332510": "purple",
    "336611": "orange",
    "336612": "darkred",
    "331511": "red",
    "331210": "blue",
    "332813": "darkblue",
    "331420": "darkgreen",
    "332618": "cadetblue",
    "212100": "purple",
    "221113": "green",
    "331221": "pink",
    "212200": "lightblue",
    "221111": "lightgreen",
    "212210": "gray",
    "486210": "black",
    "325211": "red",
    "325510": "yellow",
    "211111": "darkgray",
    "212392": "lightgray",
    "325910": "gray",
    "332420": "purple",
    "333991": "blue",
    "333200": "green",
    "333512": "purple",
    "331313": "orange",
    "331419": "darkred",
    "333611": "red",
    "332991": "darkgray",
    "423500": "darkblue",
    "331492": "darkgreen",
    "212321": "cadetblue",
    "327200": "purple",
    "326122": "red",
    "326220": "pink"
}

# Create a dictionary pairing each industry's NAICS code with an icon and color
industry_info = {}
for naics_code in industry_naics_icons.keys():
    icon = industry_naics_icons[naics_code]
    color = industry_naics_colors[naics_code]
    industry_info[naics_code] = {'icon': icon, 'color': color}
