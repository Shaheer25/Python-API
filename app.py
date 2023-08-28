from flask import Flask ,Response , request ,jsonify
import pymongo
import json
from bson.objectid import ObjectId
from flask_jwt_extended import JWTManager, create_access_token, decode_token, jwt_required, get_jwt_identity
import bcrypt
from datetime import timedelta


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "jhfshgfghsfags"
jwt = JWTManager(app)
try:
    mongo = pymongo.MongoClient(
        host="localhost",
        port=27017,
        serverSelectionTimeoutMS=1000
    )
    db = mongo.crud
    mongo.server_info()
except:
    print("Error - Connecting to DB")

@app.route('/users', methods =['POST'])
def create():  # put application's code here
    try:
        user={
            "name":request.json["name"],
            "dob":request.json["dob"]
        }
        dbResponse = db.users.insert_one(user)
        # print(dbResponse.inserted_id)
        return Response (
            response=json.dumps(
                {"message":"User Created",
                 "id":f"{dbResponse.inserted_id}"
                  }),
            status=200,
            mimetype="application/json"
        )
        # for attribute in dir(dbResponse):
        #     print(attribute)
    except Exception as ex:
        print(ex)

@app.route("/users", methods =["GET"])
def get():
    try:
        data = list(db.users.find())
        for user in data :
            user["_id"]= str(user["_id"])

        return Response(
            response=json.dumps(data),
            status=200,
            mimetype="application/json"
        )
    except Exception as ex:
        print(ex)
        return Response (
            response=json.dumps(
                {"message": "Cannot read Users",}),
            status=500,
            mimetype="application/json"
        )
@app.route("/users/<id>", methods=["PUT"])
def update(id):
    try :
        update_fields = {}

        if "name" in request.json:
            update_fields["name"] = request.json["name"]

        if "dob" in request.json:
            update_fields["dob"] = request.json["dob"]

        dbResponse = db.users.update_one(
            {"_id": ObjectId(id)},
            {"$set": update_fields}
        )

        # for attr in dir(dbResponse):
        #     print(f"{attr}")
        if dbResponse.modified_count==1:
            return Response(
                response=json.dumps(
                    {"message": "User Updated Successfully", }),
                status=200,
                mimetype="application/json"
            )
        else :
            return Response(
                response=json.dumps(
                    {"message": "Nothing Updated", }),
                status=200,
                mimetype="application/json"
            )
    except Exception as ex:
        print(ex)
        return Response(
            response=json.dumps(
                {"message": "Cannot Update Users", }),
            status=500,
            mimetype="application/json"
        )
@app.route("/users/<id>",methods =["DELETE"])
def delete(id):
    try :
        dbResponse = db.users.delete_one({"_id":ObjectId(id)})
        if dbResponse.deleted_count == 1 :

            return Response(
            response=json.dumps(
                {"message": "User Deleted Successfully", "id":f"{id}"}),
            status=200,
            mimetype="application/json"
        )
        return Response(
            response=json.dumps(
                {"message": "User not Found", "id": f"{id}"}),
            status=200,
            mimetype="application/json"
        )
    except Exception as ex:
        print(ex)
        return Response(
            response=json.dumps(
                {"message":"Cannot Delete user"}
            ),
            status=500,
            mimetype="application/json"
        )


# **********
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        user = {"username": username, "password": hashed_password}
        db.users.insert_one(user)
        return jsonify({"message": "User registered successfully"}), 201
    else:
        return jsonify({"message": "Username and password are required"}), 400

# Login API
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = db.users.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        access_token_expires = timedelta(minutes=15)  # Set access token expiry time
        refresh_token_expires = timedelta(days=30)
        access_token = create_access_token(identity=username, expires_delta=access_token_expires)
        refresh_token = create_access_token(identity=username, expires_delta=refresh_token_expires)
        db.refresh_token.insert_one({"username": username, "token": refresh_token})
        return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome, {current_user}!"}), 200


@app.route("/refresh", methods=["POST"])
@jwt_required()
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify({"refresh_token": new_access_token}), 200

if __name__ == '__main__':
    app.run(port=8080, debug=True)
