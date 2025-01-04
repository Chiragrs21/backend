from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, InputFile
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext
import requests
import json
import asyncio
import random
import pdfkit  # You can also use weasyprint as an alternative
from jinja2 import Environment, FileSystemLoader
from fpdf import FPDF  # Added for PDF generation of breach data
import time  # Added for sleep to simulate fetching time

TOKEN = '7200464979:AAGqmokio8tGeKD4WNARwlrL1UgT9LFDYxg'
BACKEND_URL = 'http://127.0.0.1:5000'
AUTH_HEADER = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluMSJ9.qMeC1eyXzDUeRKdgdgx6nLhfieJTTGW1c7mf32grYkg'

# Setup Jinja2 environment
env = Environment(loader=FileSystemLoader('templates'))

# Generate a random 4-digit number


def generate_random_name():
    return str(random.randint(1000, 9999))


# Define selected options and their corresponding endpoints and templates
OPTION_MAP = {
    "Email Checker": {"option": 1, "endpoint": "email", "template": "Email.html"},
    "Phone Lookup": {"option": 2, "endpoint": "phn_location", "template": "phone.html"},
    "UserName": {"option": 3, "endpoint": "username", "template": "username_template.html"},
    "URL Scanner": {"option": 4, "endpoint": "url_scanner", "template": "Domain.html"},
    "IP Locator": {"option": 5, "endpoint": "ip6_location", "template": "IP.html"},
    "Aadhar Number": {"option": 6, "endpoint": "aadharnumber", "template": "Adhaar.html"},
    "PAN Card": {"option": 7, "endpoint": "pancard", "template": "PAN.html"},
    "Vehicle Number": {"option": 8, "endpoint": "vehiclenumber", "template": "Vehicle.html"},
    "UPI Details": {"option": 9, "endpoint": "upi", "template": "UPI.html"},
    "Breach Data Email": {"option": 10, "endpoint": "breach_data", "template": "BreachData.html"}
}

# Endpoints for breach data
endpoints = [
    "https://1864-49-207-59-36.ngrok-free.app/api/dbs/db2/member_member/email?email=",
    "https://1864-49-207-59-36.ngrok-free.app/api/dbs/db4/users/email?email=",
    "https://1864-49-207-59-36.ngrok-free.app/api/dbs/db3/user/email?email="
]
dbs = ["db2", "db4", "db3"]


def fetch_data(endpoint, search_email):
    try:
        response = requests.get(endpoint + search_email)
        response.raise_for_status()
        return {"data": response.json()}
    except requests.RequestException as err:
        print(err)
        return {"data": [], "error": str(err)}

# Create a PDF file from HTML


def create_pdf_from_html(html_content, filename='result.pdf'):
    path_to_wkhtmltopdf = 'C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe'
    pdfkit.from_string(html_content, filename, configuration=pdfkit.configuration(
        wkhtmltopdf=path_to_wkhtmltopdf))

# Create a PDF file from breach data


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


async def start(update: Update, context: CallbackContext) -> None:
    keyboard = [
        [KeyboardButton("URL Scanner")],
        [KeyboardButton("Email Checker")],
        [KeyboardButton("IP Locator")],
        [KeyboardButton("Phone Lookup")],
        [KeyboardButton("Vehicle Number")],
        [KeyboardButton("UPI Details")],
        [KeyboardButton("Aadhar Number")],
        [KeyboardButton("PAN Card")],
        [KeyboardButton("Breach Data Email")]  # Added new menu option
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text(
        'Welcome to the Menu Bot! Please choose an option:',
        reply_markup=reply_markup
    )


async def handle_message(update: Update, context: CallbackContext) -> None:
    user_text = update.message.text

    option_info = OPTION_MAP.get(user_text)
    if option_info:
        context.user_data['current_action'] = option_info
        await update.message.reply_text(f'Please send the data for "{user_text}".')
    elif context.user_data.get('current_action'):
        action_info = context.user_data['current_action']
        random_name = generate_random_name()
        selected_option = action_info['option']
        endpoint = action_info['endpoint']
        template_name = action_info['template']

        if selected_option == 10:  # Breach Data Email
            search_email = user_text
            # Notify user
            await update.message.reply_text('Fetching data, please wait...')

            # Simulate fetching time
            time.sleep(3)  # Simulate 3 seconds of processing time

            results = []
            for idx, endpoint in enumerate(endpoints):
                result = fetch_data(endpoint, search_email)
                results.append({"db": dbs[idx], **result})

            # Create a PDF file from the fetched data
            pdf_filename = f'breach_data_{random_name}.pdf'
            create_breach_pdf(results, pdf_filename)

            # Send the PDF file to the user
            with open(pdf_filename, 'rb') as pdf_file:
                await update.message.reply_document(document=InputFile(pdf_file, filename=pdf_filename))

            # Reset the current action
            context.user_data['current_action'] = None
        else:
            # Send the user input as data
            query_data = {
                "url": user_text,
                "name": random_name,
                "selectedOption": selected_option
            }

            try:
                response = requests.post(
                    f'{BACKEND_URL}/{endpoint}',
                    json=query_data,
                    # Include authentication header
                    headers={'Authorization': AUTH_HEADER}
                )
                data = response.json()

                if response.status_code == 200:
                    # Render HTML template with data
                    template = env.get_template(template_name)
                    html_content = template.render(data=data)

                    # Create a PDF file from the rendered HTML
                    pdf_filename = f'result_{random_name}.pdf'
                    create_pdf_from_html(html_content, pdf_filename)

                    # Send the PDF file to the user
                    with open(pdf_filename, 'rb') as pdf_file:
                        await update.message.reply_document(document=InputFile(pdf_file, filename=pdf_filename))

                else:
                    await update.message.reply_text(f"Error: {data.get('error', 'Unknown error')}")

            except json.JSONDecodeError:
                await update.message.reply_text('Invalid format. Please send valid data.')

            # Reset the current action
            context.user_data['current_action'] = None
    else:
        await update.message.reply_text('Unknown command. Please choose an option from the menu.')


def main():
    application = Application.builder().token(TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND, handle_message))
    application.run_polling()


if __name__ == '__main__':
    asyncio.run(main())
