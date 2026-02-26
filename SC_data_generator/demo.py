import json

from fixed_tree_sample_generator import generate_fixed_tree_samples





def to_jsonable(node):

    """Convert datetime.date objects to ISO string for JSON export."""

    node = dict(node)

    node["start_day"] = node["start_day"].isoformat()

    node["end_day"] = node["end_day"].isoformat()

    return node





def main():

    # Load config

    with open("config.json", "r") as f:

        config = json.load(f)



    ddl_date = config["ddl_date"]

    tree_spec = config["tree"]

    params = config["params"]



    # Generate sample

    nodes = generate_fixed_tree_samples(

        ddl_date=ddl_date,

        tree_spec=tree_spec,

        load_days_range=tuple(params["load_days_range"]),

        transit_days_range=tuple(params["transit_days_range"]),

        window_days_range=tuple(params["window_days_range"]),

    )



    # Convert dates to strings

    json_nodes = [to_jsonable(n) for n in nodes]



    # Save to file

    with open("sample.json", "w") as f:

        json.dump(json_nodes, f, indent=2)



    print("Sample successfully written to sample.json")





if __name__ == "__main__":

    main()