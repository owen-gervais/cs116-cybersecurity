import requests
from bs4 import BeautifulSoup
import os


'''
fuzz()

    input: price -> input fuzz field
           beverage -> input fuzz field
           name -> input fuzz field

    output: r -> response from the fuzz test

    Forms a fuzz post request pinging the fields of the web application
'''
def fuzz(price, beverage, name): 
    request_url = "http://www.cs.tufts.edu/comp/120/hackme.php"
    payload = {"price" : price,
            "beverage" : beverage,
            "fullname" : name,
            "submitBtn" : "Go%21"} 
    r = requests.post(url = request_url, data = payload)
    return r


'''
parseResponse()

    input: response -> requests object reflecting the respoonse of the fuzz
            request.

    output: echoed_results -> dictionary of input fields echoed fuzz responses

    Utilizes BeautifulSoup in order to parse the return HTML body and parse the 
    <div id="results"> section for input field values.

'''
def parseResponse(response):
    echoed_results = {}
    soup = BeautifulSoup(response.text, 'html.parser')
    print(response.text)
    results = soup.find(id="results").text.splitlines()
    print(results)
    echoed_results["name"] = results[1][6:]
    echoed_results["price"] = results [2][29:]
    echoed_results["beverage"] = results[3][26:(results[3].find("..."))]
    return echoed_results



# Main loop operation to fuzz the web application

if __name__ == "__main__":

    fuzzerListPath = input("Enter the path to your SecLists Fuzzing folder: ")
    extension = ".txt"

    for subdir, dirs, files in os.walk(fuzzerListPath):
        for file in files:
            ext = os.path.splitext(file)[-1].lower()
            if ext == extension:
                print (os.path.join(subdir, file))

    

    name = "Sammyhoihoihoihpoihoishoihhsoihoiehoihoihoihoihoihoihoihoihoihoihd"
    price = "\'\';!--\"<XSS>=&{()}"
    beverage = "thoishoidhoshfodishoisdhf hios "

    response = fuzz(price, beverage, name)
    echoed_results = parseResponse(response)

    if name == echoed_results["name"]:
        print("XSS Vulnerability detected! Nonsanitized user input echoed back to user in the " + "NAME" + " field")
    if price == echoed_results["price"]:
        print("XSS Vulnerability detected! Nonsanitized user input echoed back to user in the " + "PRICE" + " field")
    if beverage == echoed_results["beverage"]:
        print("XSS Vulnerability detected! Nonsanitized user input echoed back to user in the " + "BEVERAGE" + " field")
    
    print(fuzzerListPath)
