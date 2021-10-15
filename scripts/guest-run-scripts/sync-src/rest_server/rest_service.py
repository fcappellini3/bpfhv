from flask import Flask, Response, request
import json
import silly_computations as sc


# Every Flask server must have a global variable instance of Flask that represent the Flask
# application itself
app = Flask(__name__)

# Set this variable to True to enable Flask's DEBUG feature
FLASK_DEBUG = False


def start_rest_service(host: str, port: int):
    """
    Start the Flask server
    """
    # Configure Flask app
    app.config["DEBUG"] = FLASK_DEBUG
    # Launch Flask app. This function is blocking!
    app.run(host=host, port=port)


@app.route("/test", methods=['GET'])
def test():
    """
    This is a test endpoint used to check if the server is running
    """
    return Response("<h1>Test</h1>", status=200, mimetype='text/html')


@app.route("/fibonacci/<n>", methods=['GET'])
def fibonacci(n):
    try:
        n = int(n)
    except ValueError as error:
        return Response("Bad Request: " + str(error), status=400, mimetype='text/plain')

    if n > 15:
        response_dict = {"warning": "I will not compute that :D"}
    else:
        response_dict = {"response": sc.fibonacci(n)}
    return Response(json.dumps(response_dict), status=200, mimetype='application/json')


@app.route("/multiple_fibonacci", methods=['POST'])
def multiple_fibonacci():
    # Retrieve number_list
    try:
        number_list = json.loads(request.form["number_list"])
    except KeyError:
        return Response("Bad Request", status=400, mimetype='text/plain')
    except json.JSONDecodeError:
        return Response("Bad Request", status=400, mimetype='text/plain')

    # Checks
    if not isinstance(number_list, list) or not all(isinstance(n, int) for n in number_list):
        return Response("Bad Request: malformed list", status=400, mimetype='text/plain')

    # Response
    response_dict = {"response": [sc.fibonacci(n) for n in number_list]}
    return Response(json.dumps(response_dict), status=200, mimetype='application/json')


@app.route("/random_stream/<size>", methods=['GET'])
def random_stream(size):
    try:
        size = int(size)
    except ValueError as error:
        return Response("Bad Request: " + str(error), status=400, mimetype='text/plain')

    stream = sc.random_stream(size)
    response_dict = {"response": list(stream)}
    return Response(json.dumps(response_dict), status=200, mimetype='application/json')


@app.route("/wordcount", methods=['POST'])
def wordcount():
    # Retrieve text
    try:
        text = request.form["text"]
    except KeyError:
        return Response("Bad Request", status=400, mimetype='text/plain')

    return Response(json.dumps(sc.wordcount(text)), status=200, mimetype='application/json')


@app.route("/vulnerable", methods=['GET'])
def vulnerable():
    var = request.args["var"]
    return Response(
        "<html><body><div>" +
        f"Someone set variable var to {var}" +
        "</div></body></html>",
        status=200, mimetype='text/html'
    )
