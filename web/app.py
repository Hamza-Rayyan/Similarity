from flask import *
from flask_restful import Api, Resource
import os
import bcrypt
from pymongo import MongoClient
import spacy

app = Flask(__name__)
api = Api(app)
Client = MongoClient('mongodb://db:27017')
db = Client.aNewDB
users = db["users"]

def UserExists(username):
    if users.count_documents({"username": username}) == 0:
        return False
    else:
        return True

def verify_pw(username, password):
    if not UserExists(username):
        return False
    hash_pw = users.find({"username": username})[0]["password"]
    if bcrypt.hashpw(password.encode('utf8'), hash_pw) == hash_pw:
        return True
    else:
        return False

def countTokens(username):
    num_tokens = users.find({"username": username})[0]["tokens"]
    return num_tokens

class Registration(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        if UserExists(username):
            retjson = {
                "Status": 301,
                "Message": "Invalid username"
            }
            return jsonify(retjson)
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        users.insert_one({
            "username": username,
            "password": hashed_pw,
            "tokens": 6
        })
        retjson = {
            "Status": 200,
            "Message": "You have Successfully signed up"
        }
        return jsonify(retjson)

class Detect(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]
        if not UserExists(username):
            retjson = {
                "Status": 301,
                "Message": "User does not exist"
            }
            return jsonify(retjson)

        correct_pw = verify_pw(username, password)
        if not correct_pw:
            retjson = {
                "Status": 302,
                "message": "Invalid Password"
            }
            return jsonify(retjson)

        num_tokens = countTokens(username)
        if num_tokens <= 0:
            retjson = {
                "Status": 303,
                "Message": "Insufficient Tokens"
            }
            return jsonify(retjson)
        import spacy
        nlp = spacy.load('en_core_web_sm')

        text1 = nlp(text1)
        text2 = nlp(text2)
        ratio=text1.similarity(text2)
        retjson = {
            "Status": 200,
            "Similarity": ratio,
            "Message": "Similarity Score Calculated Successfully"
        }
        current_tokens = users.find({"username": username})[0]["tokens"]
        users.update_one({"username": username}, {"$set": {"tokens": current_tokens - 1}})
        return jsonify(retjson)

class Refill(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["admin_pw"]
        refill_tokens = postedData["refill"]
        if not UserExists(username):
            retjson = {
                "Status": 301,
                "Message": "User does not exist"
            }
            return jsonify(retjson)
        correct = "1234"
        if not password == correct:
            retjson = {
                "Status": 304,
                "Message": "Invalid Admin Password"
            }
            return jsonify(retjson)
        users.update_one({"username": username}, {"$set": {"tokens": refill_tokens}})
        retjson = {
            "Status": 200,
            "Message": "Refilled Successfully",
        }
        return jsonify(retjson)

api.add_resource(Registration, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refill, '/refill')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
