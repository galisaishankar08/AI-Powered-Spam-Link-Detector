from ExtractUrlFeatures import UrlFeatureExtract
import pickle


def rf_classifier_predict(url):
    single_url_features = UrlFeatureExtract(url).run()
    features = single_url_features.copy()
    del features['url']
    del features['is_vulnerable']
    # Convert dictionary values to a list
    feature_values = list(features.values())

    # Make predictions using the trained model
    model_filename = './models/rf_classifier_model.pkl'
    with open(model_filename, 'rb') as model_file:
        rf_classifier = pickle.load(model_file)
    prediction = rf_classifier.predict([feature_values])

    print(prediction)
    # Interpret the prediction (e.g., 1 for spam, 0 for not spam)
    if prediction[0]:
        result = "Spam"
    else:
        result = "Not Spam"

    print(f"The URL is classified as: {result}")

    return result


url = 'http://freakinghugeurl.com'
res = rf_classifier_predict(url)
print(res)
