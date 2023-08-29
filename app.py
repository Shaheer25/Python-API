from flask import Flask ,Response , request ,jsonify
import pymongo
import json
from bson.objectid import ObjectId
from flask_jwt_extended import JWTManager, create_access_token, decode_token, jwt_required, get_jwt_identity
import bcrypt
from datetime import timedelta

app = Flask(__name__)
jwt = JWTManager(app)
app.config["JWT_SECRET_KEY"] = "jhfshgfghsfags"
try :
    mongo=pymongo.MongoClient(
        host="localhost",
        port=27017,
    )
    db=mongo.test
    mongo.server_info()
except :
    print("Error Connecting to DB")

@app.route("/users",methods=["POST"])

def create():
    try:
        users = {
            "firstName":request.json["firstName"],
            "lastName":request.json["lastName"],
            "email":request.json["email"],
            "phone":request.json["phone"],
            "userType":request.json["userType"]
        }

        dbResponse = db.users.insert_one(users)

        return Response(
            response=json.dumps({
                "message":"User Added Successfully",
                "id":f"{dbResponse.inserted_id}"
            }),
            status=200,
            mimetype="application/json"
        )
    except Exception as exp:
        print(exp)

@app.route("/users",methods=["GET"])
def get():
    try:
        data = list(db.users.find())
        for user in data :
            user["_id"]=str(user["_id"])
        return Response (
            response=json.dumps(data),
            status=200,
            mimetype="application/json"
        )
    except Exception as exp:
        print(exp)
    return Response(
        response=json.dumps({
            "message":"error while fetching user"
        }),
        status = 500,
        mimetype="application/json"
    )

@app.route("/users/<id>",methods=["PUT"])
def update(id):
     try:
        fields={}

        if "firstName" in request.json:
            fields["firstName"] = request.json["firstName"]

        if "email" in request.json:
            fields["email"] = request.json["email"]

        if "LastName" in request.json:
            fields["LastName"] = request.json["LastName"]

        if "phone" in request.json:
            fields["phone"] = request.json["phone"]

        dbResponse = db.users.update_one(
            {"_id": ObjectId(id)},
            {"$set": fields}
        )
        if dbResponse.modified_count == 1:
            return Response(
            response=json.dumps(
                {"message":"Updated Successfully"}
            ),
            status=200,
                mimetype="application/json"
        )
        else:
            return Response(
                response=json.dumps(
                    {"message": "Nothing to Update"}
                ),
                status=200,
                mimetype="application/json"
            )
     except Exception as exp:
         print(exp)
         return Response(
             response=json.dumps(
                 {"message": "Failed to Update"}
             ),
             status=500,
             mimetype="application/json"
         )
@app.route("/users/<id>",methods=["DELETE"])
def delete(id):
    try:
        dbResponse=db.users.delete_one({"_id":ObjectId(id)})
        if dbResponse.deleted_count==1 :
            return Response(
                response=json.dumps({
                    "message": f"Sucessfully Deleted {id}"
                }),
                status=200,
                mimetype="application/json"
            )
        else :
            return Response(
                response=json.dumps({
                    "message": "Nothing to Delete"
                }),
                status=400,
                mimetype="application/json"
            )

    except Exception as exp:
        print(exp)
    return Response(
        response=json.dumps({
            "message":"Failed to Delete"
        }),
        status=500,
        mimetype="application/json"
    )
@app.route("/user/<id>",methods=["GET"])
def getone(id):
    try:
        dbResponse =db.users.find_one({"_id":ObjectId(id)})
        return Response(
            response=json.dumps({
                "data": f"{dbResponse}"
            }),
            status=200,
            mimetype="application/json"
        )

    except Exception as exp:
        print(exp)
        return Response(
            response=json.dumps({
                "message": "Failed fetch"
            }),
            status=500,
            mimetype="application/json"
        )


# ********************JWT*******************************

@app.route("/users/signup",methods=["POST"])
def signup():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if email and password :
            check_email= db.signup.find_one({"email":email})
            if check_email:
                return jsonify({"message": "email already Exists"}), 401
            hashed_password = bcrypt.hashpw(password.encode("utf-8"),bcrypt.gensalt())
            user={"email":email , "password":hashed_password}
            dbResponse = db.signup.insert_one(user)
            return jsonify({"message":"user created Successful ","id":f"{dbResponse.inserted_id}"}),201
        else :
            return jsonify({"message": "user not created"}), 500

    except Exception as exp:
        print(exp)
        return Response(
            response=json.dumps({
                "message": "Failed to add user"
            }),
            status=500,
            mimetype="application/json"
        )

@app.route("/users/login",methods=["POST"])
def login():
    try:
        data= request.get_json()
        email = data.get("email")
        password = data.get("password")

        user = db.signup.find_one({"email":email})
        if user and bcrypt.hashpw(password.encode("utf-8"),user["password"]):
            access_token_expiry = timedelta(minutes=15)
            refresh_token_expiry= timedelta(days=7)
            access_token=create_access_token(identity="username",expires_delta=access_token_expiry)
            refresh_token = create_access_token(identity="username", expires_delta=refresh_token_expiry)
            return jsonify({"data":{"access_token":f"{access_token}",}}) , 200
        else:
            return jsonify({"message":"Invalid Credentials"})

    except Exception as exp:
        print(exp)
        return Response(
            response=json.dumps({
                "message": "Failed Login In"
            }),
            status=500,
            mimetype="application/json")

@app.route("/refreshtoken",methods=["GET"])
@jwt_required()
def refresh_token():
    users = db.signup
    user = get_jwt_identity()
    expiry = timedelta(days=7)
    refresh_token = create_access_token(user,expires_delta=expiry)
    db.refreshToken.insert_one({"email": f"{users.email}", "refresh_token": refresh_token})
    return jsonify({"refresh_token":f"{refresh_token}"}),200


@app.route("/home",methods=["GET"])
@jwt_required()
def protected():
    check = get_jwt_identity()
    if check :
        return jsonify({}),200


if __name__ == '__main__':
    app.run(port=8000, debug=True)