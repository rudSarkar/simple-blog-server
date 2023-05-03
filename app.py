from datetime import timedelta
from flask import Flask, Blueprint, jsonify, request
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, get_jwt, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from flask_cors import CORS

ACCESS_EXPIRES = timedelta(hours=1)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
CORS(app)

blog_db = mysql.connector.connect(
    host="db",
    user="rabbi",
    password="password12345",
    database="blog_app"
)

jwt = JWTManager(app)
BLOCKLIST = set()

user_blueprint = Blueprint('user', __name__)
user_api = Api(user_blueprint)


@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, decrypted_token):
    jti = decrypted_token['jti']
    return jti in BLOCKLIST


class Register(Resource):
    def post(self):
        try:
            email = request.form['email']
            password = generate_password_hash(request.form['password'])
            name = request.form['name']

            cursor = blog_db.cursor()
            insert_query = "INSERT INTO users (email, password, name) VALUES (%s, %s, %s)"
            cursor.execute(insert_query, (email, password, name))
            blog_db.commit()

            return jsonify({'message': 'User created successfully!'})
        except Exception as e:
            return jsonify({'error': str(e)})


class Login(Resource):
    def post(self):
        try:
            email = request.form['email']
            password = request.form['password']

            cursor = blog_db.cursor()
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user is None:
                return jsonify({'error': 'Invalid email or password'})
            elif check_password_hash(user[2], password):
                access_token = create_access_token(
                    identity={'id': user[0], 'email': user[1]})
                return jsonify({'access_token': access_token})
            else:
                return jsonify({'error': 'Invalid email or password'})
        except Exception as e:
            return jsonify({'error': str(e)})


class Logout(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return jsonify({'message': f'Successfully logged out.'})


class Posts(Resource):
    @jwt_required()
    def get(self):
        cursor = blog_db.cursor()
        cursor.execute("SELECT * FROM posts ORDER BY id DESC")
        result = cursor.fetchall()

        if result:
            return jsonify(result)
        return jsonify({
            'message': 'No blogs found'
        })

class Dashboard(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()['id']
        cursor = blog_db.cursor()
        cursor.execute("SELECT * FROM posts WHERE user_id = %s ORDER BY id DESC", (user_id,))
        result = cursor.fetchall()

        if result:
            posts = []
            for row in result:
                post = {
                    'id': row[0],
                    'title': row[1],
                    'content': row[2],
                    'user_id': row[3],
                    'created_at': row[4].strftime('%a, %d %b %Y %H:%M:%S GMT')
                }
                posts.append(post)
            return jsonify(posts)
        return jsonify({
            'message': 'No posts found for this user'
        })

class NewPost(Resource):
    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()['id']
        title = request.form['title']
        body = request.form['body']

        cursor = blog_db.cursor()
        insert_query = "INSERT INTO posts (user_id, title, body) VALUES (%s, %s, %s)"
        cursor.execute(insert_query, (user_id, title, body))
        blog_db.commit()

        return jsonify({'message': 'Post created successfully!'})


user_api.add_resource(Posts, '/')
user_api.add_resource(Register, '/register')
user_api.add_resource(Login, '/login')
user_api.add_resource(Logout, '/logout')
user_api.add_resource(Dashboard, '/dashboard')
user_api.add_resource(NewPost, '/post')

app.register_blueprint(user_blueprint)

if __name__ == '__main__':
    app.run(debug=True)
