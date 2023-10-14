from flask import *
from detect import Detect_Url

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/', methods=['POST'])
def scan():
    if request.method == "POST":
        url = request.form["url"]
        is_spam = Detect_Url(url).run()

        res = {
            'is_spam': is_spam,
        }
        return render_template("index.html", result=res)
    return redirect('/')


@app.route('/app/verify', methods=['GET'])
def vefify():
    url = request.args.get('url')
    if url:
        is_spam_url = Detect_Url(url).run()
        if is_spam_url:
            return render_template('warning.html')

        return redirect(url)
    return 'URL parameter "url" not provided. Ex: http://127.0.0.1:5000/app/verify?url=https://www.google.com'


@app.route('/api/verify', methods=['GET', 'POST'], strict_slashes=False)
def api():
    print(jsonify(request.json))
    if request.json['url']:
        url = str(request.json['url'])
        res = Detect_Url(url).run()
        if res:
            return 'True'
        return 'False'
    return "Error"


if __name__ == '__main__':
    app.run(debug=True)
