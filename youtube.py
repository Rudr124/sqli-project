import csv
from faker import Faker

def generate_fake_emails(num_emails=50):
    """Generate fake emails for educational purposes"""
    fake = Faker()
    emails = [fake.email() for _ in range(num_emails)]
    return emails

def save_to_csv(emails, filename="fake_emails.csv"):
    """Save generated emails to CSV"""
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Email Address"])
        for email in emails:
            writer.writerow([email])
    print(f"✅ Saved {len(emails)} fake emails to {filename} (for educational use only).")

if __name__ == "__main__":
    print("🔹 Educational Email Generator (Fake Data Only) 🔹")
    num_emails = int(input("How many fake emails to generate? (e.g., 50): ") or 50)
    
    fake_emails = generate_fake_emails(num_emails)
    save_to_csv(fake_emails)