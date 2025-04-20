import os

from flask import Flask, request

from config import Config
from routes.insecure import configure_insecure_routes
from routes.secure import configure_secure_routes

app = Flask(__name__)

# Configure upload folder
os.makedirs(Config.UPLOAD_FOLDER.value, exist_ok=True)
app.config["UPLOAD_FOLDER"] = Config.UPLOAD_FOLDER.value
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH.value


# Add is_xml property to request
@app.before_request
def before_request():
    request.is_xml = request.content_type == "application/xml"


# Configure routes
configure_insecure_routes(app)
configure_secure_routes(app)


@app.route("/")
def index():
    return "XXE Demo API - Check /insecure and /secure endpoints"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
