import whois
from datetime import datetime
from pyquery import PyQuery
from requests import get
import vt
import nest_asyncio
from dotenv import load_dotenv
import os
load_dotenv()


class UrlFeatureExtract(object):
    def __init__(self, url):
        self.url = url
        self.domain = url.split('//')[-1].split('/')[0]
        self.today = datetime.now().replace(tzinfo=None)

        try:
            self.whois = whois.query(self.domain).__dict__
        except:
            self.whois = None

        try:
            self.response = get(self.url)
            self.pq = PyQuery(self.response.text)
        except:
            self.response = None
            self.pq = None

    def numDigits(self):
        digits = [i for i in self.url if i.isdigit()]
        return len(digits)

    def urlLength(self):
        return len(self.url)

    def numParameters(self):
        params = self.url.split('&')
        return len(params) - 1

    def hasHttp(self):
        return 'http:' in self.url

    def hasHttps(self):
        return 'https:' in self.url

    def numTitles(self):
        if self.pq is not None:
            titles = ['h{}'.format(i) for i in range(7)]
            titles = [self.pq(i).items() for i in titles]
            return len([item for s in titles for item in s])
        else:
            return 0

    def numImages(self):
        if self.pq is not None:
            return len([i for i in self.pq('img').items()])
        else:
            return 0

    def numLinks(self):
        if self.pq is not None:
            return len([i for i in self.pq('a').items()])
        else:
            return 0

    def specialCharacters(self):
        if self.pq is not None:
            bodyText = self.pq('html').text()
            schars = [i for i in bodyText if not i.isdigit()
                      and not i.isalpha()]
            return len(schars)
        else:
            return 0

    def urlIsLive(self):
        return self.response == 200

    def scan(self):
        API_KEY = os.getenv('API_KEY')
        nest_asyncio.apply()

        # Get the URL's ID from VirusTotal
        with vt.Client(API_KEY) as client:
            url_id = vt.url_id(self.url)
            url = client.get_object("/urls/{}", url_id)

        # Convert the URL information to a dictionary
        du = url.to_dict()

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
        extracted_data = {
            'threats': threats,
            'total_type_of_threats': total_type_of_threats,
            'redirection_chain_count': rcc,
            'total_threats': total_threats,
            'is_vulnerable': False
        }

        # Determine if the URL is malicious based on specific criteria
        if extracted_data.get('threats', {}).get('malware') > 0:
            extracted_data['is_vulnerable'] = True
        elif extracted_data.get('threats', {}).get('phishing') > 3:
            extracted_data['is_vulnerable'] = True
        elif extracted_data.get('redirection_chain_count') > 3:
            extracted_data['is_vulnerable'] = True
        elif extracted_data.get('total_type_of_threats') > 3:
            extracted_data['is_vulnerable'] = True
        elif extracted_data.get('total_threats') > 5:
            extracted_data['is_vulnerable'] = True

        return extracted_data

    def run(self):
        try:
            sc_data = self.scan()
            # print(self.url)
            features = {}
            features['url'] = self.url
            features['numDigits'] = self.numDigits()
            features['urlLength'] = self.urlLength()
            features['numParams'] = self.numParameters()
            features['hasHttp'] = int(self.hasHttp())
            features['hasHttps'] = int(self.hasHttps())
            features['numTitles'] = self.numTitles()
            features['numImages'] = self.numImages()
            features['numLinks'] = self.numLinks()
            features['specialChars'] = self.specialCharacters()

            for i in sc_data.get('threats'):
                features[i] = sc_data.get('threats', {}).get(i)
            features['total_type_of_threats'] = sc_data.get(
                'total_type_of_threats')
            features['redirection_chain_count'] = sc_data.get(
                'redirection_chain_count')
            features['total_threats'] = sc_data.get('total_threats')
            features['is_vulnerable'] = sc_data.get('is_vulnerable')

            only_threats = sc_data['threats'].copy()
            del only_threats['unrated']
            del only_threats['clean']

            features['threats'] = only_threats

            return features
        except Exception as e:
            print(e)
            return None


# url = 'https://colab.research.google.com/'
# out = UrlFeatureExtract(url).run()
# print(out)


# is_spam = Detect_Url(
#     'http://bomberospuertomontt.cl/modules/0299970236/105328892193242/index2.php').run()
# print(is_spam)
