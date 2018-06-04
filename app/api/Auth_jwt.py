# -*- coding: utf-8 -*-
import jwt, datetime, time
from flask import jsonify
from  model.User import User as Users
from config import db,SECRET_KEY
from lib import common

class Authors():
    @staticmethod
    def encode_auth_token(user_id, login_time):
        """
        生成认证Token
        :param user_id: int
        :param login_time: int(timestamp)
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=10),
                'iat': datetime.datetime.utcnow(),
                'iss': 'ken',
                'data': {
                    'id': user_id,
                    'login_time': login_time
                }
            }
            return jwt.encode(
                payload,
                SECRET_KEY,
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        验证Token
        :param auth_token:
        :return: integer|string
        """
        try:
            # payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'), leeway=datetime.timedelta(seconds=10))
            # 取消过期时间验证

            payload = jwt.decode(auth_token, SECRET_KEY, options={'verify_exp': False})
            if ('data' in payload and 'id' in payload['data']):
                return payload
            else:
                raise jwt.InvalidTokenError
        except jwt.ExpiredSignatureError:
            return 'Token过期'
        except jwt.InvalidTokenError:
            return '无效Token'


    def authenticate(self, username, password):
        """
        用户登录，登录成功返回token，写将登录时间写入数据库；登录失败返回失败原因
        :param password:
        :return: json
        """
        userInfo = Users.query.filter_by(user_name=username).first()
        if (userInfo is None):
            return jsonify(common.falseReturn('', '找不到用户'))
        else:
            if (userInfo.check_pwd(password)) :
                login_time = int(time.time())
                userInfo.login_time = login_time
                token = self.encode_auth_token(userInfo.id, login_time)

                userInfo.user_token = token

                db.session.add(userInfo)
                db.session.commit()
                return jsonify(common.trueReturn(token.decode('utf-8'), '登录成功'))
            else:
                return jsonify(common.falseReturn('', '密码不正确'))

    def identify(self, request):
        """
        用户鉴权
        :return: list
        """
        auth_header = request.headers.get('Authorization')
        if (auth_header):
            auth_tokenArr = auth_header.split(" ")
            if (not auth_tokenArr or auth_tokenArr[0] != 'JWT' or len(auth_tokenArr) != 2):
                result = common.falseReturn('', '请传递正确的验证头信息')
            else:
                auth_token = auth_tokenArr[1]
                payload = self.decode_auth_token(auth_token)
                if not isinstance(payload, str):

                    user = Users.query.filter_by(id = payload['data']['id']).first()
                    if (user is None):
                        result = common.falseReturn('', '找不到该用户信息')
                    else:

                        if (user.login_time == payload['data']['login_time']):
                            result = common.trueReturn(user.id, '请求成功')
                        else:
                            result = common.falseReturn('', 'Token已更改，请重新登录获取')
                else:
                    result = common.falseReturn('', payload)
        else:
            result = common.falseReturn('', '没有提供认证token')
        return result

