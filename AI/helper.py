import pandas as pd
import time
from tqdm import tqdm
import logging
from ExtractUrlFeatures import UrlFeatureExtract

# Set up a logger
logging.basicConfig(filename='feature_extraction.log', level=logging.ERROR)

# Load the CSV file containing URLs
# Replace with the path to your input CSV file
input_csv_path = './input/keras-malicious-url-dataset.csv'
# Replace with the path to your output CSV file
output_csv_path = './out/url_featured_data.csv'

# Define a function to extract features from a URL using the UrlFeatureExtract class


def extract_url_features(url, retry_limit=1):
    retries = 0
    while retries < retry_limit:
        try:
            url_features = UrlFeatureExtract(url).run()
            # Pause for 20 seconds to respect VirusTotal's API rate limits
            time.sleep(20)
            return url_features
        except Exception as e:
            logging.error(
                f"Error extracting features for URL: {url}, Retry: {retries + 1}")
            logging.error(str(e))
            retries += 1
            time.sleep(20)  # Pause before retrying
    return None


# Load the input CSV file into a DataFrame
df = pd.read_csv(input_csv_path)

# Create an empty list to store extracted features
extracted_features = []

# Batch size for saving extracted features
batch_size = 10

# Loop through the URLs and extract features
with tqdm(total=len(df)) as pbar:
    for idx, row in df.iterrows():
        url = row['url']
        features = extract_url_features(url)
        if features:
            extracted_features.append(features)

        # Save features in batches with a timestamp to avoid data loss on error
        if len(extracted_features) >= batch_size:
            timestamp = time.strftime("%Y%m%d%H%M%S")
            print(timestamp)
            features_df = pd.DataFrame(extracted_features)
            features_df.to_csv(output_csv_path, mode='a',
                               header=True, index=False)
            extracted_features = []

        pbar.update(1)

# Save any remaining extracted features
if extracted_features:
    features_df = pd.DataFrame(extracted_features)
    features_df.to_csv(output_csv_path, mode='a', header=False, index=False)

print(f"Extracted features saved at {output_csv_path}")
