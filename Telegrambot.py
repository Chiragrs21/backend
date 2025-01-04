from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, InputFile
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext
import requests
import json
import asyncio
import random
import pdfkit
from jinja2 import Environment, FileSystemLoader
from fpdf import FPDF
import bcrypt
import jwt
from pymongo import MongoClient
import string

TOKEN = '7200464979:AAGqmokio8tGeKD4WNARwlrL1UgT9LFDYxg'
BACKEND_URL = 'http://127.0.0.1:5000'
SECRET_KEY = 'wedbjviu2e'

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['mydatabase2']

env = Environment(loader=FileSystemLoader('templates'))


def generate_random_name():
    # Generate 2 digits
    digits_part = str(random.randint(10, 99))  # Ensures 2 digits

    # Generate 3 letters (A-Z)
    letters_part = ''.join(random.choices(string.ascii_uppercase, k=3))

    # Generate 2 more digits
    digits_part2 = str(random.randint(10, 99))  # Ensures 2 digits

    # Generate 1 letter (A-Z)
    single_letter = random.choice(string.ascii_uppercase)  # Ensures 1 letter

    # Combine all parts
    return f"{digits_part}{letters_part}{digits_part2}{single_letter}"


OPTION_MAP = {
    "Email Checker": {"option": "1", "endpoint": "email", "template": "Email.html"},
    "Phone Lookup": {"option": "2", "endpoint": "phn_location", "template": "phone.html"},
    "UserName": {"option": "3", "endpoint": "username", "template": "username_template.html"},
    "URL Scanner": {"option": "4", "endpoint": "url_scanner", "template": "Domain.html"},
    "IP Locator": {"option": "5", "endpoint": "ip6_location", "template": "IP.html"},
    "Aadhar Number": {"option": "6", "endpoint": "aadharnumber", "template": "Adhaar.html"},
    "PAN Card": {"option": "7", "endpoint": "pancard", "template": "PAN.html"},
    "Vehicle Number": {"option": "8", "endpoint": "vehiclenumber", "template": "Vehicle.html"},
    "UPI Details": {"option": "9", "endpoint": "upi", "template": "UPI.html"},
    "Breach Data Email": {"option": "10", "endpoint": "breach_data", "template": "BreachData.html"},
    # New option for checking credit balance
    "Check Credit Balance": {"option": "11"}
}


endpoints = [
    "https://6dfe-106-51-185-20.ngrok-free.app/api/dbs/db2/member_member/email?email=",
    "https://6dfe-106-51-185-20.ngrok-free.app/api/dbs/db4/users/email?email=",
    "https://6dfe-106-51-185-20.ngrok-free.app/api/dbs/db3/user/email?email="
]
dbs = ["db2", "db4", "db3"]


def fetch_data(endpoint, search_email):
    try:
        response = requests.get(endpoint + search_email)
        response.raise_for_status()  # This will raise an exception for HTTP error responses
        return {"data": response.json()}
    except requests.RequestException as err:
        print(f"Error fetching data from {endpoint}: {err}")
        return {"data": [], "error": f"Error fetching data: {err}"}


def create_pdf_from_html(html_content, filename='result.pdf'):
    path_to_wkhtmltopdf = 'C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe'
    pdfkit.from_string(html_content, filename, configuration=pdfkit.configuration(
        wkhtmltopdf=path_to_wkhtmltopdf))


def create_breach_pdf(data, filename='breach_data.pdf'):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    for entry in data:
        pdf.cell(200, 10, txt=f"Database: {entry['db']}", ln=True, align='L')
        if "error" in entry:
            pdf.cell(
                200, 10, txt=f"Error: {entry['error']}", ln=True, align='L')
        else:
            pdf.multi_cell(0, 10, txt=json.dumps(entry["data"], indent=4))

    pdf.output(filename)


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def verify_password(stored_hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)


def verify_token(token):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return data.get('username')
    except jwt.ExpiredSignatureError:
        return None
    except (jwt.InvalidTokenError, IndexError):
        return None


async def start(update: Update, context: CallbackContext) -> None:
    await update.message.reply_text('Please enter your username:')
    context.user_data['auth_step'] = 'username'


async def authenticate_user(update: Update, context: CallbackContext) -> None:
    auth_step = context.user_data.get('auth_step')

    if auth_step == 'username':
        context.user_data['username'] = update.message.text
        await update.message.reply_text('Please enter your password:')
        context.user_data['auth_step'] = 'password'
    elif auth_step == 'password':
        username = context.user_data['username']
        password = update.message.text

        user = db.users.find_one({'username': username})

        if user and verify_password(user['password'], password):
            token = jwt.encode({'username': username},
                               SECRET_KEY, algorithm='HS256')
            context.user_data['auth_token'] = f'Bearer {token}'

            await update.message.reply_text('Login successful!')
            context.user_data['auth_step'] = None
            await show_menu(update)
        else:
            await update.message.reply_text('Invalid username or password. Please try again.')
            context.user_data['auth_step'] = 'username'
    elif auth_step is None:
        user_text = update.message.text
        option_info = OPTION_MAP.get(user_text)
        if option_info:
            context.user_data['current_action'] = option_info
            if user_text == "Check Credit Balance":
                await check_credit_balance(update, context)
            else:
                await update.message.reply_text(f'Please send the data for "{user_text}".')
        elif context.user_data.get('current_action'):
            action_info = context.user_data['current_action']
            random_name = generate_random_name()
            selected_option = action_info['option']
            endpoint = action_info['endpoint']
            template_name = action_info['template']

            if selected_option == "10":
                search_email = user_text
                await update.message.reply_text('Fetching data, please wait...')

                results = []
                for idx, endpoint in enumerate(endpoints):
                    result = fetch_data(endpoint, search_email)
                    results.append({"db": dbs[idx], **result})

                pdf_filename = f'breach_data_{random_name}.pdf'
                create_breach_pdf(results, pdf_filename)

                with open(pdf_filename, 'rb') as pdf_file:
                    await update.message.reply_document(document=InputFile(pdf_file, filename=pdf_filename))

                context.user_data['current_action'] = None
            else:
                query_data = {
                    "url": user_text,
                    "name": random_name,
                    "selectedOption": selected_option
                }

                try:
                    auth_header = context.user_data.get('auth_token')
                    response = requests.post(
                        f'{BACKEND_URL}/{endpoint}',
                        json=query_data,
                        headers={'Authorization': auth_header}
                    )
                    data = response.json()

                    if response.status_code == 200:
                        template = env.get_template(template_name)
                        html_content = template.render(data=data)

                        pdf_filename = f'result_{random_name}.pdf'
                        create_pdf_from_html(html_content, pdf_filename)

                        with open(pdf_filename, 'rb') as pdf_file:
                            await update.message.reply_document(document=InputFile(pdf_file, filename=pdf_filename))

                    else:
                        await update.message.reply_text(f"Error: {data.get('error', 'Unknown error')}")

                except json.JSONDecodeError:
                    await update.message.reply_text('Invalid format. Please send valid data.')

                context.user_data['current_action'] = None
        else:
            await update.message.reply_text('Unknown command. Please choose an option from the menu.')


async def show_menu(update: Update) -> None:
    keyboard = [
        [KeyboardButton("URL Scanner")],
        [KeyboardButton("Email Checker")],
        [KeyboardButton("IP Locator")],
        [KeyboardButton("Phone Lookup")],
        [KeyboardButton("Vehicle Number")],
        [KeyboardButton("UPI Details")],
        [KeyboardButton("Aadhar Number")],
        [KeyboardButton("PAN Card")],
        [KeyboardButton("Breach Data Email")],
        [KeyboardButton("Check Credit Balance")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

    await update.message.reply_text(
        'What would you like to do? Choose an option to start:',
        reply_markup=reply_markup
    )


async def check_credit_balance(update: Update, context: CallbackContext) -> None:
    try:
        auth_header = context.user_data.get('auth_token')
        response = requests.get(
            f'{BACKEND_URL}/get_credit_balance',
            headers={'Authorization': auth_header}
        )

        if response.status_code == 200:
            data = response.json()
            await update.message.reply_text(f"Your credit balance: {data['credits']}")
        else:
            error_message = response.json().get('error', 'Unknown error')
            await update.message.reply_text(f"Error: {error_message}")

    except requests.RequestException as err:
        await update.message.reply_text(f"Request error: {err}")


def main() -> None:
    application = Application.builder().token(TOKEN).build()

    application.add_handler(CommandHandler('start', start))
    application.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND, authenticate_user))

    application.run_polling()


if __name__ == '__main__':
    main()
