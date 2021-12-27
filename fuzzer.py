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
def fuzz(fuzzedInput): 
    request_url = "http://www.cs.tufts.edu/comp/120/hackme.php"
    params = { "token":fuzzedInput }
    r = requests.get(url = request_url, params= params)
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
    startStr = "You set the token as " # Start string to parse out the token 
    endStr = ".  The phrase"
    soup = BeautifulSoup(response.text, 'html.parser')
    results = soup.find(id="results").text
    return results[len(startStr)+1:results.find(endStr)]


'''
mainloop()

Prompts the user to enter a path to their SecLists Fuzzing folder and then iterates through all of the files
in the folder and its children. 

'''

if __name__ == "__main__":
    
    # Prompt users SecLists folder location
    fuzzerListPath = input("Enter the path to your SecLists Fuzzing folder: ")
    extension = ".txt"
    print("-------------------------------")

    # Iterates through all of the files in the Fuzzing folder reading fuzz inputs one by one 
    for subdir, dirs, files in os.walk(fuzzerListPath):

        for file in files:

            ext = os.path.splitext(file)[-1].lower() # Check for the extension '.txt'

            if ext == extension:

                # Print status of fuzzer during operation to the console 
                print ("Fuzzing application using: " + os.path.join(subdir, file))
                print(" ")
                try: 
                    file = open(os.path.join(subdir, file), "r")
                    fuzzStrs = file.readlines()

                    vulnerable = False
                    i = 0

                    # Checks to see if the 
                    while not vulnerable:
                        # Initial assumption is that the first lines are comments
                        comment = True
                        # Increment through the file until you get to the first non comment
                        while comment: 
                            if fuzzStrs[i].find("# ") == 0:
                                i+=1
                            else: 
                                comment = False
                        # Fuzz the web application
                        response = fuzz(fuzzStrs[i])
                        # As long as there is a successful get request
                        if response.status_code == 200:
                            echoed_token = parseResponse(response)
                            if echoed_token == fuzzStrs[i]:
                                print("XSS VULNERABILITY DETECTED!!!!")
                                print("")
                                print("    INPUT: " + fuzzStrs[i])
                                print("    OUTPUT: " + echoed_token)
                                print("")
                                print("-------------------------------")
                                vulnerable = True
                            i+=1
                        # If the request is not authorized go to the next one
                        else: 
                            i+=1
                except: 
                    print("Error in accessing the current file moving to the next file in the current working directory .... ")
                    print("-------------------------------")
                    continue


