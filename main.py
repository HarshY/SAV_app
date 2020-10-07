from get_registration import getRegistration, getDomain

def main():
    print("Please enter domain name: ")
    user_input = input()
    domain_name = getDomain(user_input)
    expiry_date = getRegistration(domain_name)
    print(f"The expiration date is: {expiry_date}")

if __name__ == "__main__":
    main()