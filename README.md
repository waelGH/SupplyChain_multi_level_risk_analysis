# SupplyChainDash application

## Setup

The first thing to do is to clone the repository:

# Clone from GitHub
```sh
$ git clone https://github.com/k3smith/supply-chain-dash.git
```

Create a virtual environment to install dependencies in and activate it:

```sh
$ python -m venv .venv
$ source .venv/bin/activate
```

Then install the dependencies:

```sh
(.venv)$ pip install -r requirements.txt
```
Note the `(.venv)` in front of the prompt. This indicates that this terminal
session operates in a virtual environment.

## Environment Configuration

**IMPORTANT**: Before running the application, you need to set up your environment variables.

1. Copy the example environment file:
```sh
cp env.example .env
```

2. Edit the `.env` file and add your actual API keys:
   - **FRED_API_KEY**: Get your FRED API key from [Federal Reserve Bank of St. Louis - FRED](https://fred.stlouisfed.org/docs/api/api_key.html)
   - **NVD_API_KEY**: Get your NVD API key from [NIST NVD](https://nvd.nist.gov/developers/request-an-api-key)
   - **OPENAI_API_KEY**: Get your OpenAI API key from [OpenAI Platform](https://platform.openai.com/api-keys)
   - **SECRET_KEY**: Generate a new Django secret key (see instructions below)

### Generating a Django Secret Key

You can generate a secure Django secret key using several methods:

**Method 1: Using OpenSSL (recommended - no Python required):**
```bash
openssl rand -base64 32
```

**Method 2: Using Python (if you prefer):**
```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

**Method 3: Using Python secrets module:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

**Method 4: Using /dev/urandom (Linux/Mac):**
```bash
head -c 32 /dev/urandom | base64
```

Copy the generated key and paste it as the value for `SECRET_KEY` in your `.env` file.

Example `.env` file:
```
SECRET_KEY=django-insecure-your-generated-secret-key-here
FRED_API_KEY=your-fred-api-key-here
NVD_API_KEY=your-nvd-api-key-here
OPENAI_API_KEY=your-openai-api-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
```

## Generate data files
```sh
python utility\data_gen_suppliers.py
python utility\data_mappers_parts.py
```

## Run Django
**If this is the first time running the Django app, follow the steps in the "To Migrate" section below first.**

Once `pip` has finished downloading the dependencies:
```sh
(.venv)$ cd SupplyChainPlanning
(.venv)$ python manage.py runserver
```
And navigate to `http://127.0.0.1:8000/mainDash/`.

### Loading Data files
You will need to load the data files you generated `mock_bom_data.csv` and `mock_supplier_data.csv` the first time you run the dashboard application. There are green buttons in the lower left corner to "Link Data Sets". 

## Admin 
### Access
URL: http://127.0.0.1:8000/admin/
Username: admin
Password: admin

## Database Setup

**First time setup:** Run these commands to set up the database:

```sh
(.venv)$ python manage.py makemigrations
```

```sh
(.venv)$ python manage.py migrate
```

**Note:** The `makemigrations` command creates migration files for any model changes, and `migrate` applies those changes to the database. You only need to run `sqlmigrate` if you want to see the SQL that will be executed (optional).
