import vt
import nest_asyncio
import os
from dotenv import load_dotenv

load_dotenv()


class Detect_Url():
    def __init__(self, url):
        self.url = url

    def detect(self):
        # Your VirusTotal API key
        API_KEY = os.getenv('API_KEY')

        # Initialize the VirusTotal client
        # vt_client = vt.Client(API_KEY)

        # Apply nest_asyncio to allow asynchronous code within this synchronous context
        # nest_asyncio.apply()

        # url_id = vt.url_id(self.url)
        # url = client.get_object("/urls/{}", url_id)

        # Close the VirusTotal client
        # vt_client.close()

        # Apply nest_asyncio to allow asynchronous code within this synchronous context
        nest_asyncio.apply()

        # Get the URL's ID from VirusTotal
        with vt.Client(API_KEY) as client:
            url_id = vt.url_id(self.url)
            url = client.get_object("/urls/{}", url_id)

        # Convert the URL information to a dictionary
        du = url.to_dict()
        # print(du)

        # Get the last analysis results
        lar = du.get('attributes', {}).get('last_analysis_results')

        # Initialize a dictionary to count different types of threats
        threats = {
            'malware': 0,
            'phishing': 0,
            'suspicious': 0,
            'clean': 0,
            'unrated': 0,
            'malicious': 0,
        }

        # Count the occurrences of each threat type
        for l in lar.values():
            t = l.get('result', 'unrated')
            threats[t] = threats.get(t, 0) + 1

        # Create a copy of the threats dictionary excluding 'unrated' and 'clean' threats
        only_threats = threats.copy()
        del only_threats['unrated']
        del only_threats['clean']

        # Count the total number of distinct threat types
        total_type_of_threats = 0
        for i in only_threats.values():
            if i > 0:
                total_type_of_threats += 1

        # Count the number of redirections in the URL
        rcc = 0
        if du.get('attributes', {}).get('redirection_chain'):
            rcc = len(du.get('attributes', {}).get('redirection_chain'))

        # Calculate the total number of threats (excluding 'unrated' and 'clean')
        total_threats = sum(t for t in only_threats.values())

        # Create a dictionary containing the extracted data
        self.extracted_data = {
            'threats': threats,
            'total_type_of_threats': total_type_of_threats,
            'redirection_chain_count': rcc,
            'total_threats': total_threats,
        }

        # Determine if the URL is malicious based on specific criteria
        if self.extracted_data.get('threats', {}).get('malware') > 0:
            return True
        elif self.extracted_data.get('threats', {}).get('phishing') > 3:
            return True
        elif self.extracted_data.get('redirection_chain_count') > 3:
            return True
        elif self.extracted_data.get('total_type_of_threats') > 3:
            return True
        elif self.extracted_data.get('total_threats') > 5:
            return True

        # If none of the criteria match, return False
        return False, self.extracted_data
    
    def run(self):
        try:
            is_malicious, data = self.detect()

            only_threats = data['threats'].copy()
            del only_threats['unrated']
            del only_threats['clean']

            # Count the total number of distinct threat types
            only_threat = []
            for i in only_threats:
                if only_threats[i] > 0:
                    only_threat.append(i)
            analysed_data = {
                'url' : self.url,
                'threats': only_threat,
                'redirection_chain_count': data['redirection_chain_count']
            }

            # Return whether the URL is malicious (True) or not (False)
            return is_malicious, analysed_data
        except Exception as e:
            print(e)
            return ''

is_spam = Detect_Url('http://bomberospuertomontt.cl/modules/0299970236/105328892193242/index2.php').run()
print(is_spam)