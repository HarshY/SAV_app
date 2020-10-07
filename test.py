from get_registration import getRegistration, getDomain

def main():
    test_file = open("./test.txt", encoding="utf-8")
    test_list = test_file.read().splitlines()
    for i in range(0, len(test_list)):
        print(f"Test {i}:")
        url = test_list[i]
        print(f"Input: {url}")
        domain_name = getDomain(url)
        print(f"Domain: {domain_name}")
        expiry_date = getRegistration(domain_name)
        print(f"The expiration date is: {expiry_date}")
        print()
    print("Done Testing")

if __name__ == "__main__":
    main()