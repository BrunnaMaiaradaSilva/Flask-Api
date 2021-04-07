from flask import Flask
from flask_restful import Resource, reqparse
from models.usuario import UserModel
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
# from flask_jwt_extended import get_jwt_identity
from werkzeug.security import safe_str_cmp
from blacklist import BLACKLIST


atributos = reqparse.RequestParser()
atributos.add_argument('login', type=str, required=True)
atributos.add_argument('senha', type=str, required=True)


class User(Resource):

    def get(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            return user.json()
        return {'message': 'User not found'}, 404

    @jwt_required()
    def delete(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            try:
                user.delete_user()
            except InternalError:
                return {"message": "An internal error occurred"}, 500
            return {'message': 'User deleted.'}
        return {'message': 'User not found.'}, 404


class UserRegister(Resource):
    def post(self):
        dados = atributos.parse_args()

        if UserModel.find_by_login(dados['login']):
            return {'message': 'User {} exists'.format(dados['login'])}
        user = UserModel(**dados)
        user.save_user()
        return {'message': 'User created.'}, 201


class UserLogin(Resource):

    @classmethod
    def post(cls):
        dados = atributos.parse_args()

        user = UserModel.find_by_login(dados['login'])

        if user and safe_str_cmp(user.senha, dados['senha']):
            token_de_acesso = create_access_token(identity=user.user_id)
            return {'acess_token': token_de_acesso}, 200
        return {'message': 'User or pass incorrect'}, 401


class UserLogout(Resource):

    @jwt_required()
    def post(self):
        jwt_id = get_jwt()['jti']
        BLACKLIST.add(jwt_id)
        return {'message': 'Logged out'}, 200
