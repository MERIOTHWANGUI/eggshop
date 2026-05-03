# EggShop – E-commerce Platform for Egg Distribution 🥚

A web-based e-commerce system for ordering eggs per crate, integrated with M-Pesa for payments and Africa's Talking for automated delivery notifications.

---

## Problem
Small-scale egg vendors often lack a streamlined system to manage orders, payments, and customer communication efficiently.

---

## Solution
EggShop provides an online platform where customers can place orders for eggs, make payments via M-Pesa, and receive automated SMS notifications confirming delivery.

---

## Features
- Order eggs per crate through a web interface
- M-Pesa payment integration for secure transactions
- SMS notifications using Africa's Talking API
- Order tracking and confirmation
- Backend system for managing orders

---

## System Architecture
- **Frontend:** HTML/CSS (Flask templates)
- **Backend:** Python (Flask)
- **Database:** SQLite / PostgreSQL
- **Payment Integration:** M-Pesa (STK Push / API)
- **Messaging API:** Africa's Talking

---

## Tech Stack
- Python
- Flask
- SQLite / PostgreSQL
- M-Pesa API
- Africa's Talking API

---

## How It Works
1. User selects quantity (crates of eggs)
2. Order is submitted through the web interface
3. M-Pesa STK Push is triggered for payment
4. Payment confirmation is processed by the backend
5. Order is marked as complete
6. SMS notification is sent to the customer via Africa's Talking

---
##screenshots
landing page/homepage/order page
<img width="1353" height="598" alt="image" src="https://github.com/user-attachments/assets/fc024f85-41fd-4bfa-9db7-e4a0eeec83c5" />
<img width="1316" height="630" alt="image" src="https://github.com/user-attachments/assets/46ba77f9-094e-4eaf-9fa8-58eda6c92156" />
<img width="760" height="645" alt="image" src="https://github.com/user-attachments/assets/c809ba16-378b-4cce-961d-fe661ff3b276" />
##about us
<img width="1249" height="556" alt="image" src="https://github.com/user-attachments/assets/d812f95b-a5cf-4598-adcd-4beb399cc59f" />
<img width="1105" height="667" alt="image" src="https://github.com/user-attachments/assets/2822f73e-10c9-458c-9703-ee0d18961619" />
<img width="1021" height="643" alt="image" src="https://github.com/user-attachments/assets/bcc0986b-8fb7-488a-b8fe-37f13ccea0b7" />
contact us
<img width="585" height="497" alt="image" src="https://github.com/user-attachments/assets/cce8abd3-3590-4db9-9407-4fe274c04e04" />

<img width="651" height="553" alt="image" src="https://github.com/user-attachments/assets/81c37308-d243-4035-9807-76e5570ab978" />


## Installation

```bash
git clone https://github.com/yourusername/eggshop.git
cd eggshop
pip install -r requirements.txt
python app.py
